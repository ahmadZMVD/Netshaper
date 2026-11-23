package main

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

// XrayConfig models the subset of V2Ray/Xray config.json audited by UT-11 and UT-12.
type XrayConfig struct {
	Log struct {
		LogLevel string `json:"loglevel"`
	} `json:"log"`
	DNS struct {
		QueryStrategy string            `json:"queryStrategy"`
		Hosts         map[string]any    `json:"hosts"`
		Servers       []json.RawMessage `json:"servers"`
		Tag           string            `json:"tag"`
	} `json:"dns"`
	Inbounds []struct {
		Tag      string `json:"tag"`
		Port     int    `json:"port"`
		Listen   string `json:"listen"`
		Protocol string `json:"protocol"`
		Sniffing struct {
			Enabled      bool     `json:"enabled"`
			DestOverride []string `json:"destOverride"`
			RouteOnly    bool     `json:"routeOnly"`
		} `json:"sniffing"`
		Settings struct {
			Auth             string `json:"auth"`
			UDP              bool   `json:"udp"`
			AllowTransparent bool   `json:"allowTransparent"`
		} `json:"settings"`
	} `json:"inbounds"`
	Outbounds []struct {
		Tag      string `json:"tag"`
		Protocol string `json:"protocol"`
		Mux      *struct {
			Enabled     bool `json:"enabled"`
			Concurrency int  `json:"concurrency"`
		} `json:"mux,omitempty"`
	} `json:"outbounds"`
	Routing struct {
		DomainStrategy string `json:"domainStrategy"`
		Rules          []struct {
			Type        string   `json:"type"`
			Port        string   `json:"port"`
			Network     string   `json:"network"`
			InboundTag  []string `json:"inboundTag"`
			IP          []string `json:"ip"`
			Domain      []string `json:"domain"`
			OutboundTag string   `json:"outboundTag"`
		} `json:"rules"`
	} `json:"routing"`
}

// ParseXrayConfig unmarshals raw JSON bytes into XrayConfig.
func ParseXrayConfig(raw []byte) (*XrayConfig, error) {
	var cfg XrayConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse xray config: %w", err)
	}
	return &cfg, nil
}

// ValidateXrayRoutingRules enforces UT-11 invariants:
// 1. rules[0] MUST block udp:443 (QUIC fail-fast).
// 2. Every DNS inboundTag rule MUST precede the catch-all proxy rule (no shadowing).
// 3. Non-direct UDP traffic MUST NOT be able to reach outboundTag "proxy".
// 4. proxy outbound mux MUST be disabled against OpenSSH -D SOCKS5.
func ValidateXrayRoutingRules(cfg *XrayConfig) error {
	rules := cfg.Routing.Rules
	if len(rules) == 0 {
		return fmt.Errorf("routing.rules is empty")
	}

	r0 := rules[0]
	if r0.Port != "443" || !strings.EqualFold(r0.Network, "udp") || r0.OutboundTag != "block" {
		return fmt.Errorf("rules[0] must block udp:443, got port=%q network=%q outboundTag=%q", r0.Port, r0.Network, r0.OutboundTag)
	}

	catchAllIdx := -1
	udpBlockedBeforeProxy := false

	for i, r := range rules {
		isCatchAll := r.OutboundTag == "proxy" && (r.Port == "0-65535" || (r.Port == "" && len(r.IP) == 0 && len(r.Domain) == 0 && len(r.InboundTag) == 0))
		if isCatchAll && catchAllIdx == -1 {
			catchAllIdx = i
		}
		if catchAllIdx == -1 && r.OutboundTag == "block" && strings.EqualFold(r.Network, "udp") && r.Port == "" {
			udpBlockedBeforeProxy = true
		}
	}

	if catchAllIdx == -1 {
		return fmt.Errorf("no catch-all proxy rule found in routing.rules")
	}

	dnsTagFound := false
	for i, r := range rules {
		for _, tag := range r.InboundTag {
			if strings.Contains(strings.ToLower(tag), "dns") {
				dnsTagFound = true
				if i >= catchAllIdx {
					return fmt.Errorf("DNS rule at index %d (inboundTag=%q) is shadowed by catch-all proxy rule at index %d", i, tag, catchAllIdx)
				}
			}
		}
	}
	if !dnsTagFound {
		return fmt.Errorf("no DNS inboundTag routing rule found")
	}

	catchAll := rules[catchAllIdx]
	catchAllAcceptsUDP := catchAll.Network == "" || strings.Contains(strings.ToLower(catchAll.Network), "udp")
	inboundUDP := false
	for _, in := range cfg.Inbounds {
		if in.Settings.UDP {
			inboundUDP = true
		}
	}
	if catchAllAcceptsUDP && !udpBlockedBeforeProxy {
		return fmt.Errorf("catch-all proxy rule at index %d allows UDP (network=%q) without a preceding blanket UDP block rule", catchAllIdx, catchAll.Network)
	}
	if inboundUDP && !udpBlockedBeforeProxy {
		return fmt.Errorf("inbound enables UDP without a blanket UDP block rule before proxy")
	}

	for _, out := range cfg.Outbounds {
		if out.Tag == "proxy" && out.Mux != nil && out.Mux.Enabled {
			return fmt.Errorf("proxy outbound mux must be false for OpenSSH -D SOCKS5")
		}
	}

	return nil
}

// ValidateXrayDNSConfig enforces UT-12 invariants (and v6 multi-DoH resilience):
// 1. Zero plaintext UDP:53 servers (bare IPv4/IPv6 addresses).
// 2. Zero DoT TCP:853 servers (tls:// or :853).
// 3. Zero Alibaba China DNS (223.5.5.5).
// 4. Verified DoH servers (https://1.1.1.1/dns-query & https://8.8.8.8/dns-query; optional Quad9 9.9.9.9) MUST be present.
// 5. queryStrategy=UseIPv6 is forbidden on IPv4-only WAN links.
func ValidateXrayDNSConfig(cfg *XrayConfig) error {
	if len(cfg.DNS.Servers) == 0 {
		return fmt.Errorf("dns.servers is empty")
	}
	if strings.EqualFold(strings.TrimSpace(cfg.DNS.QueryStrategy), "UseIPv6") {
		return fmt.Errorf("dns.queryStrategy=UseIPv6 is forbidden on IPv4-only WAN network")
	}

	hasCFDoH := false
	hasGoogleDoH := false

	for i, raw := range cfg.DNS.Servers {
		var addr string
		if err := json.Unmarshal(raw, &addr); err != nil {
			var obj struct {
				Address string `json:"address"`
			}
			if err2 := json.Unmarshal(raw, &obj); err2 != nil {
				return fmt.Errorf("dns.servers[%d]: invalid entry: %w", i, err2)
			}
			addr = obj.Address
		}
		addr = strings.TrimSpace(addr)
		lower := strings.ToLower(addr)

		if addr == "" {
			return fmt.Errorf("dns.servers[%d]: empty address", i)
		}
		if net.ParseIP(addr) != nil {
			return fmt.Errorf("dns.servers[%d]: plaintext UDP:53 IP %q forbidden", i, addr)
		}
		if strings.Contains(lower, "223.5.5.5") {
			return fmt.Errorf("dns.servers[%d]: Alibaba China DNS %q forbidden", i, addr)
		}
		if strings.HasPrefix(lower, "tls://") || strings.Contains(lower, ":853") {
			return fmt.Errorf("dns.servers[%d]: DoT:853 %q forbidden", i, addr)
		}
		if !strings.HasPrefix(lower, "https://") {
			return fmt.Errorf("dns.servers[%d]: expected verified DoH https:// resolver, got %q", i, addr)
		}

		if lower == "https://1.1.1.1/dns-query" {
			hasCFDoH = true
		}
		if lower == "https://8.8.8.8/dns-query" {
			hasGoogleDoH = true
		}
	}

	if !hasCFDoH {
		return fmt.Errorf("missing verified Cloudflare DoH server https://1.1.1.1/dns-query")
	}
	if !hasGoogleDoH {
		return fmt.Errorf("missing verified Google DoH server https://8.8.8.8/dns-query")
	}
	return nil
}

// ValidateXrayConfig runs both UT-11 routing and UT-12 DNS validations.
func ValidateXrayConfig(raw []byte) error {
	cfg, err := ParseXrayConfig(raw)
	if err != nil {
		return err
	}
	if err := ValidateXrayRoutingRules(cfg); err != nil {
		return err
	}
	if err := ValidateXrayDNSConfig(cfg); err != nil {
		return err
	}
	return nil
}
