package main

import (
	"strings"
)

// DefaultCleanupAllowedImages strictly whitelists only NetShaper/tunnel binaries.
// xray.exe is NEVER included and will NEVER be terminated.
var DefaultCleanupAllowedImages = []string{
	"NetShaper.exe",
	"gh.exe",
	"ssh.exe",
}

// TCPListenerEntry describes a single OS TCP listening socket.
type TCPListenerEntry struct {
	Port   uint16
	PID    uint32
	Family string // "tcp4" or "tcp6"
}

// PortInspector abstracts Win32 IP Helper + process inspection for production & unit tests.
type PortInspector interface {
	ListListeners() ([]TCPListenerEntry, error)
	ProcessImageName(pid uint32) (string, error)
	TerminatePID(pid uint32) error
}

// CleanupAuditRecord records every port-cleanup decision for forensic logging and testing.
type CleanupAuditRecord struct {
	Port      uint16
	PID       uint32
	Family    string
	ImageName string
	Action    string // KILLED, SKIPPED_SELF, SKIPPED_WHITELIST, SKIPPED_IMAGE_ERR, KILL_FAILED
	Err       string
}

func baseImageName(imagePath string) string {
	s := strings.TrimSpace(imagePath)
	if idx := strings.LastIndexAny(s, `/\`); idx >= 0 {
		s = s[idx+1:]
	}
	return s
}

func isAllowedImage(imageName string, allowed []string) bool {
	base := baseImageName(imageName)
	if base == "" || base == "." {
		return false
	}
	for _, a := range allowed {
		if strings.EqualFold(base, a) {
			return true
		}
	}
	return false
}

// CleanTargetPorts inspects active TCP listeners and terminates ONLY exact uint16 port
// matches belonging to whitelisted image names, explicitly excluding selfPID.
func CleanTargetPorts(
	inspector PortInspector,
	targetPorts []uint16,
	selfPID uint32,
	allowedImages []string,
	logger *EventLogger,
) ([]CleanupAuditRecord, error) {
	if inspector == nil || len(targetPorts) == 0 {
		return nil, nil
	}
	if len(allowedImages) == 0 {
		allowedImages = DefaultCleanupAllowedImages
	}

	targetSet := make(map[uint16]struct{}, len(targetPorts))
	for _, p := range targetPorts {
		if p == 0 {
			continue
		}
		targetSet[p] = struct{}{}
	}
	if len(targetSet) == 0 {
		return nil, nil
	}

	entries, err := inspector.ListListeners()
	if err != nil {
		if logger != nil {
			logger.Log("PORT_CLEANUP_AUDIT", map[string]any{
				"action": "ENUM_FAILED",
				"error":  err.Error(),
			})
		}
		return nil, err
	}

	seenPIDPort := make(map[uint64]struct{})
	killedPIDs := make(map[uint32]bool)
	var records []CleanupAuditRecord

	for _, entry := range entries {
		if _, match := targetSet[entry.Port]; !match {
			continue
		}
		if entry.PID == 0 {
			continue
		}
		key := (uint64(entry.PID) << 16) | uint64(entry.Port)
		if _, dup := seenPIDPort[key]; dup {
			continue
		}
		seenPIDPort[key] = struct{}{}

		rec := CleanupAuditRecord{
			Port:   entry.Port,
			PID:    entry.PID,
			Family: entry.Family,
		}

		if entry.PID == selfPID {
			rec.Action = "SKIPPED_SELF"
			records = append(records, rec)
			logCleanupRecord(logger, rec)
			continue
		}

		img, imgErr := inspector.ProcessImageName(entry.PID)
		rec.ImageName = baseImageName(img)
		if imgErr != nil {
			rec.Action = "SKIPPED_IMAGE_ERR"
			rec.Err = imgErr.Error()
			records = append(records, rec)
			logCleanupRecord(logger, rec)
			continue
		}

		if !isAllowedImage(rec.ImageName, allowedImages) {
			rec.Action = "SKIPPED_WHITELIST"
			records = append(records, rec)
			logCleanupRecord(logger, rec)
			continue
		}

		if killedPIDs[entry.PID] {
			rec.Action = "ALREADY_KILLED"
			records = append(records, rec)
			logCleanupRecord(logger, rec)
			continue
		}

		if killErr := inspector.TerminatePID(entry.PID); killErr != nil {
			rec.Action = "KILL_FAILED"
			rec.Err = killErr.Error()
		} else {
			rec.Action = "KILLED"
			killedPIDs[entry.PID] = true
		}
		records = append(records, rec)
		logCleanupRecord(logger, rec)
	}

	return records, nil
}

func logCleanupRecord(logger *EventLogger, rec CleanupAuditRecord) {
	if logger == nil {
		return
	}
	fields := map[string]any{
		"port":   rec.Port,
		"pid":    rec.PID,
		"family": rec.Family,
		"image":  rec.ImageName,
		"action": rec.Action,
	}
	if rec.Err != "" {
		fields["error"] = rec.Err
	}
	logger.Log("PORT_CLEANUP_AUDIT", fields)
}
