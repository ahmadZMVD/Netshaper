package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockPortInspector simulates OS TCP listener tables and process images for UT-01 and ST-06.
type mockPortInspector struct {
	mu         sync.Mutex
	listeners  []TCPListenerEntry
	images     map[uint32]string
	imageErrs  map[uint32]error
	termErrs   map[uint32]error
	terminated []uint32
}

func (m *mockPortInspector) ListListeners() ([]TCPListenerEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]TCPListenerEntry, len(m.listeners))
	copy(out, m.listeners)
	return out, nil
}

func (m *mockPortInspector) ProcessImageName(pid uint32) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err, ok := m.imageErrs[pid]; ok {
		return "", err
	}
	if img, ok := m.images[pid]; ok {
		return img, nil
	}
	return "", fmt.Errorf("pid %d not found", pid)
}

func (m *mockPortInspector) TerminatePID(pid uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err, ok := m.termErrs[pid]; ok {
		return err
	}
	m.terminated = append(m.terminated, pid)
	return nil
}

func (m *mockPortInspector) TerminatedCopy() []uint32 {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]uint32, len(m.terminated))
	copy(out, m.terminated)
	return out
}

// TestHelperProcess is invoked as a subprocess by UT-02, UT-05, UT-09, UT-14..UT-22, ST-02..ST-13.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	mode := os.Getenv("HELPER_MODE")
	switch mode {
	case "sleep_alive":
		time.Sleep(120 * time.Second)
		os.Exit(0)

	case "hang_60s":
		time.Sleep(60 * time.Second)
		os.Exit(0)

	case "crash_stderr_255":
		delayMS, _ := strconv.Atoi(os.Getenv("HELPER_DELAY_MS"))
		if delayMS > 0 {
			time.Sleep(time.Duration(delayMS) * time.Millisecond)
		}
		_, _ = fmt.Fprintln(os.Stderr, "Timeout, server not responding.")
		os.Exit(255)

	case "crash_429":
		delayMS, _ := strconv.Atoi(os.Getenv("HELPER_DELAY_MS"))
		if delayMS > 0 {
			time.Sleep(time.Duration(delayMS) * time.Millisecond)
		}
		_, _ = fmt.Fprintln(os.Stderr, "HTTP 429: You have exceeded a secondary rate limit. Please wait a few minutes before you try again.")
		os.Exit(1)

	case "crash_404":
		delayMS, _ := strconv.Atoi(os.Getenv("HELPER_DELAY_MS"))
		if delayMS > 0 {
			time.Sleep(time.Duration(delayMS) * time.Millisecond)
		}
		_, _ = fmt.Fprintln(os.Stderr, "getting full codespace details: HTTP 404: Not Found (https://api.github.com/user/codespaces/my-codespace?internal=true&refresh=true)")
		os.Exit(1)

	case "spawn_tree":
		br := bufio.NewReader(os.Stdin)
		_, _ = br.ReadString('\n')

		child := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
		child.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1", "HELPER_MODE=sleep_alive")
		if err := child.Start(); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "spawn grandchild failed: %v\n", err)
			os.Exit(2)
		}
		_, _ = fmt.Fprintf(os.Stdout, "PARENT=%d CHILD=%d\n", os.Getpid(), child.Process.Pid)
		time.Sleep(120 * time.Second)
		os.Exit(0)
	}
	os.Exit(0)
}

func newHelperCmd(mode string, extraEnv ...string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
	env := append(os.Environ(), "GO_WANT_HELPER_PROCESS=1", "HELPER_MODE="+mode)
	env = append(env, extraEnv...)
	cmd.Env = env
	ConfigureChildCmd(cmd)
	return cmd
}

// mockHalfCloseServer verifies TCP FIN half-close propagation and progress-resetting drains.
type mockHalfCloseServer struct {
	ln           net.Listener
	payload      []byte
	payloadHash  [32]byte
	stallForever atomic.Bool
	wg           sync.WaitGroup
}

func startMockHalfCloseServer(t *testing.T, delay time.Duration, payloadSize int) *mockHalfCloseServer {
	t.Helper()
	return startMockChunkedHalfCloseServer(t, delay, payloadSize, payloadSize, 0)
}

func startMockChunkedHalfCloseServer(t *testing.T, initialDelay time.Duration, payloadSize int, chunkSize int, chunkDelay time.Duration) *mockHalfCloseServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("half-close server listen: %v", err)
	}
	payload := makeDeterministicPayload(payloadSize, 3030)
	srv := &mockHalfCloseServer{
		ln:          ln,
		payload:     payload,
		payloadHash: sha256.Sum256(payload),
	}
	srv.wg.Add(1)
	go func() {
		defer srv.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			srv.wg.Add(1)
			go func(conn net.Conn) {
				defer srv.wg.Done()
				defer conn.Close()
				_, _ = io.Copy(io.Discard, conn)
				if srv.stallForever.Load() {
					time.Sleep(30 * time.Second)
					return
				}
				if initialDelay > 0 {
					time.Sleep(initialDelay)
				}
				cs := chunkSize
				if cs <= 0 || cs > len(srv.payload) {
					cs = len(srv.payload)
				}
				for off := 0; off < len(srv.payload); off += cs {
					end := off + cs
					if end > len(srv.payload) {
						end = len(srv.payload)
					}
					if _, err := conn.Write(srv.payload[off:end]); err != nil {
						return
					}
					if chunkDelay > 0 && end < len(srv.payload) {
						time.Sleep(chunkDelay)
					}
				}
				if cw, ok := conn.(closeWriter); ok {
					_ = cw.CloseWrite()
				}
			}(c)
		}
	}()
	return srv
}

func (s *mockHalfCloseServer) Addr() string { return s.ln.Addr().String() }
func (s *mockHalfCloseServer) Close() {
	_ = s.ln.Close()
	s.wg.Wait()
}

type socksServerMode int32

const (
	socksModeNormal socksServerMode = iota
	socksModeTCPOnly
	socksModeBlackhole
	socksModeConnectOnlyNoData // answers RFC 1928 CONNECT then blackholes application data (tests v6 Stage 2 micro-payload)
)

// mockSOCKS5Server implements RFC 1928 no-auth CONNECT + bidirectional echo with configurable latency/modes.
type mockSOCKS5Server struct {
	ln           net.Listener
	mode         atomic.Int32
	handshakeMS  atomic.Int64
	inFlight     atomic.Int64
	maxInFlight  atomic.Int64
	connectCount atomic.Int64
	mu           sync.Mutex
	conns        map[net.Conn]struct{}
	wg           sync.WaitGroup
}

func startMockSOCKS5Server(t *testing.T, mode socksServerMode) *mockSOCKS5Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mock SOCKS5 listen: %v", err)
	}
	s := &mockSOCKS5Server{
		ln:    ln,
		conns: make(map[net.Conn]struct{}),
	}
	s.mode.Store(int32(mode))
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns[c] = struct{}{}
			s.mu.Unlock()

			cur := s.inFlight.Add(1)
			for {
				prev := s.maxInFlight.Load()
				if cur <= prev || s.maxInFlight.CompareAndSwap(prev, cur) {
					break
				}
			}

			s.wg.Add(1)
			go func(conn net.Conn) {
				defer s.wg.Done()
				defer func() {
					s.inFlight.Add(-1)
					s.mu.Lock()
					delete(s.conns, conn)
					s.mu.Unlock()
					_ = conn.Close()
				}()

				curMode := socksServerMode(s.mode.Load())
				if curMode == socksModeTCPOnly || curMode == socksModeBlackhole {
					var sink [64]byte
					for {
						if _, err := conn.Read(sink[:]); err != nil {
							return
						}
					}
				}

				if delay := s.handshakeMS.Load(); delay > 0 {
					time.Sleep(time.Duration(delay) * time.Millisecond)
				}

				var greet [2]byte
				if _, err := io.ReadFull(conn, greet[:]); err != nil {
					return
				}
				if greet[0] != 0x05 {
					return
				}
				methods := make([]byte, int(greet[1]))
				if _, err := io.ReadFull(conn, methods); err != nil {
					return
				}
				if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
					return
				}

				var reqHdr [4]byte
				if _, err := io.ReadFull(conn, reqHdr[:]); err != nil {
					return
				}
				var addrLen int
				switch reqHdr[3] {
				case 0x01:
					addrLen = 4
				case 0x04:
					addrLen = 16
				case 0x03:
					var lb [1]byte
					if _, err := io.ReadFull(conn, lb[:]); err != nil {
						return
					}
					addrLen = int(lb[0])
				default:
					return
				}
				addrPort := make([]byte, addrLen+2)
				if _, err := io.ReadFull(conn, addrPort); err != nil {
					return
				}

				// RFC 1928 reply: VER=5, REP=0 (succeeded), RSV=0, ATYP=1, BND=127.0.0.1:0
				if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}); err != nil {
					return
				}
				s.connectCount.Add(1)

				if curMode == socksModeConnectOnlyNoData {
					var sink [256]byte
					for {
						if _, err := conn.Read(sink[:]); err != nil {
							return
						}
					}
				}

				// Bidirectional echo until client FIN or close.
				buf := make([]byte, 32*1024)
				for {
					n, rerr := conn.Read(buf)
					if n > 0 {
						if _, werr := conn.Write(buf[:n]); werr != nil {
							return
						}
					}
					if rerr != nil {
						if cw, ok := conn.(closeWriter); ok {
							_ = cw.CloseWrite()
						}
						return
					}
				}
			}(c)
		}
	}()
	return s
}

func (s *mockSOCKS5Server) Addr() string { return s.ln.Addr().String() }
func (s *mockSOCKS5Server) Port(t *testing.T) uint16 {
	t.Helper()
	_, p, err := net.SplitHostPort(s.Addr())
	if err != nil {
		t.Fatalf("split port: %v", err)
	}
	v, err := strconv.ParseUint(p, 10, 16)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return uint16(v)
}

func (s *mockSOCKS5Server) SetMode(mode socksServerMode) { s.mode.Store(int32(mode)) }
func (s *mockSOCKS5Server) SetHandshakeDelayMS(ms int64) { s.handshakeMS.Store(ms) }

func (s *mockSOCKS5Server) Close() {
	_ = s.ln.Close()
	s.mu.Lock()
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

// mockBloatedRelay injects controllable cellular latency, burst loss, and radio blackout.
type mockBloatedRelay struct {
	ln        net.Listener
	upstream  string
	minMS     atomic.Int64
	maxMS     atomic.Int64
	lossPct   atomic.Int64
	pass      atomic.Bool
	blackhole atomic.Bool
	mu        sync.Mutex
	conns     map[net.Conn]struct{}
	wg        sync.WaitGroup
}

func startMockBloatedRelay(t *testing.T, upstream string, minMS, maxMS, lossPct int64) *mockBloatedRelay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bloated relay listen: %v", err)
	}
	r := &mockBloatedRelay{
		ln:       ln,
		upstream: upstream,
		conns:    make(map[net.Conn]struct{}),
	}
	r.minMS.Store(minMS)
	r.maxMS.Store(maxMS)
	r.lossPct.Store(lossPct)
	r.pass.Store(true)

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		var cid atomic.Uint64
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			id := cid.Add(1)
			r.mu.Lock()
			r.conns[c] = struct{}{}
			r.mu.Unlock()
			r.wg.Add(1)
			go func(client net.Conn, connID uint64) {
				defer r.wg.Done()
				defer func() {
					r.mu.Lock()
					delete(r.conns, client)
					r.mu.Unlock()
					_ = client.Close()
				}()

				if r.blackhole.Load() {
					var sink [64]byte
					for {
						if _, err := client.Read(sink[:]); err != nil {
							return
						}
					}
				}

				rng := rand.New(rand.NewPCG(connID+17, connID^0x55aa))
				if lp := r.lossPct.Load(); lp > 0 && int64(rng.IntN(100)) < lp {
					time.Sleep(150 * time.Millisecond)
					return
				}

				if lo, hi := r.minMS.Load(), r.maxMS.Load(); hi > 0 {
					d := lo
					if hi > lo {
						d += int64(rng.IntN(int(hi - lo + 1)))
					}
					if d > 0 {
						time.Sleep(time.Duration(d) * time.Millisecond)
					}
				}

				up, err := net.DialTimeout("tcp", r.upstream, 2*time.Second)
				if err != nil {
					return
				}
				defer up.Close()

				var pwg sync.WaitGroup
				pwg.Add(2)
				go func() {
					defer pwg.Done()
					_, _ = io.Copy(up, client)
					if cw, ok := up.(closeWriter); ok {
						_ = cw.CloseWrite()
					}
				}()
				go func() {
					defer pwg.Done()
					_, _ = io.Copy(client, up)
					if cw, ok := client.(closeWriter); ok {
						_ = cw.CloseWrite()
					}
				}()
				pwg.Wait()
			}(c, id)
		}
	}()
	return r
}

func (r *mockBloatedRelay) Addr() string { return r.ln.Addr().String() }
func (r *mockBloatedRelay) Port(t *testing.T) uint16 {
	t.Helper()
	_, p, err := net.SplitHostPort(r.Addr())
	if err != nil {
		t.Fatalf("relay split port: %v", err)
	}
	v, _ := strconv.ParseUint(p, 10, 16)
	return uint16(v)
}

func (r *mockBloatedRelay) SetProfile(minMS, maxMS, lossPct int64, pass, blackhole bool) {
	r.minMS.Store(minMS)
	r.maxMS.Store(maxMS)
	r.lossPct.Store(lossPct)
	r.pass.Store(pass)
	r.blackhole.Store(blackhole)
}

func (r *mockBloatedRelay) SetBlackhole(v bool) { r.blackhole.Store(v) }

func (r *mockBloatedRelay) Close() {
	_ = r.ln.Close()
	r.mu.Lock()
	for c := range r.conns {
		_ = c.Close()
	}
	r.mu.Unlock()
	r.wg.Wait()
}

// startPlainTCPEchoServer starts an echo server tracking live & peak concurrency.
func startPlainTCPEchoServer(t *testing.T, holdDelay time.Duration) (string, *atomic.Int64, *atomic.Int64, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("plain echo listen: %v", err)
	}
	var cur, peak atomic.Int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			v := cur.Add(1)
			for {
				p := peak.Load()
				if v <= p || peak.CompareAndSwap(p, v) {
					break
				}
			}
			wg.Add(1)
			go func(conn net.Conn) {
				defer wg.Done()
				defer cur.Add(-1)
				defer conn.Close()
				if holdDelay > 0 {
					time.Sleep(holdDelay)
				}
				buf := make([]byte, 32*1024)
				for {
					n, rerr := conn.Read(buf)
					if n > 0 {
						if _, werr := conn.Write(buf[:n]); werr != nil {
							return
						}
					}
					if rerr != nil {
						if cw, ok := conn.(closeWriter); ok {
							_ = cw.CloseWrite()
						}
						return
					}
				}
			}(c)
		}
	}()
	stop := func() {
		_ = ln.Close()
		wg.Wait()
	}
	return ln.Addr().String(), &cur, &peak, stop
}

// shapingSensitiveUpstream blackholes any connection accepted while >maxOpen are open or <minGap since last accept.
type shapingSensitiveUpstream struct {
	ln          net.Listener
	maxOpen     int64
	minGap      time.Duration
	workDelay   time.Duration
	open        atomic.Int64
	peak        atomic.Int64
	violations  atomic.Int64
	mu          sync.Mutex
	lastAccept  time.Time
	minSeenGap  time.Duration
	conns       map[net.Conn]struct{}
	wg          sync.WaitGroup
}

func startShapingSensitiveUpstream(t *testing.T, maxOpen int64, minGap, workDelay time.Duration) *shapingSensitiveUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("shaping upstream listen: %v", err)
	}
	u := &shapingSensitiveUpstream{
		ln:         ln,
		maxOpen:    maxOpen,
		minGap:     minGap,
		workDelay:  workDelay,
		minSeenGap: time.Hour,
		conns:      make(map[net.Conn]struct{}),
	}
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			now := time.Now()
			cur := u.open.Add(1)
			for {
				p := u.peak.Load()
				if cur <= p || u.peak.CompareAndSwap(p, cur) {
					break
				}
			}

			violated := cur > u.maxOpen
			u.mu.Lock()
			u.conns[c] = struct{}{}
			if !u.lastAccept.IsZero() {
				gap := now.Sub(u.lastAccept)
				if gap < u.minSeenGap {
					u.minSeenGap = gap
				}
				if gap < u.minGap {
					violated = true
				}
			}
			u.lastAccept = now
			u.mu.Unlock()
			if violated {
				u.violations.Add(1)
			}

			u.wg.Add(1)
			go func(conn net.Conn, bad bool) {
				defer u.wg.Done()
				defer func() {
					u.open.Add(-1)
					u.mu.Lock()
					delete(u.conns, conn)
					u.mu.Unlock()
					_ = conn.Close()
				}()
				if bad {
					// Punish stampede by blackholing until client times out.
					var sink [256]byte
					for {
						if _, err := conn.Read(sink[:]); err != nil {
							return
						}
					}
				}
				data, err := io.ReadAll(conn)
				if err != nil {
					return
				}
				if u.workDelay > 0 {
					time.Sleep(u.workDelay)
				}
				_, _ = conn.Write(data)
				if cw, ok := conn.(closeWriter); ok {
					_ = cw.CloseWrite()
				}
			}(c, violated)
		}
	}()
	return u
}

func (u *shapingSensitiveUpstream) Addr() string { return u.ln.Addr().String() }
func (u *shapingSensitiveUpstream) MinSeenGap() time.Duration {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.minSeenGap
}

func (u *shapingSensitiveUpstream) Close() {
	_ = u.ln.Close()
	u.mu.Lock()
	for c := range u.conns {
		_ = c.Close()
	}
	u.mu.Unlock()
	u.wg.Wait()
}

func shapingEchoClient(addr string, payload []byte, timeout time.Duration) error {
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write(payload); err != nil {
		return err
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	got, err := io.ReadAll(c)
	if err != nil {
		return err
	}
	if len(got) != len(payload) || sha256.Sum256(got) != sha256.Sum256(payload) {
		return fmt.Errorf("echo mismatch: got=%d want=%d", len(got), len(payload))
	}
	return nil
}

func performSOCKS5EchoTransfer(proxyAddr string, payload []byte, timeout time.Duration) error {
	c, err := net.DialTimeout("tcp", proxyAddr, timeout)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))

	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	var mResp [2]byte
	if _, err := io.ReadFull(c, mResp[:]); err != nil {
		return err
	}
	if mResp[0] != 0x05 || mResp[1] != 0x00 {
		return fmt.Errorf("bad socks5 method reply %x", mResp)
	}

	req := []byte{0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0x01, 0xbb}
	if _, err := c.Write(req); err != nil {
		return err
	}
	var rep [10]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		return err
	}
	if rep[0] != 0x05 || rep[1] != 0x00 {
		return fmt.Errorf("socks5 connect failed: %x", rep)
	}

	if _, err := c.Write(payload); err != nil {
		return err
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	got, err := io.ReadAll(c)
	if err != nil {
		return err
	}
	if len(got) != len(payload) || sha256.Sum256(got) != sha256.Sum256(payload) {
		return fmt.Errorf("socks5 echo mismatch: got=%d want=%d", len(got), len(payload))
	}
	return nil
}

func holdSOCKS5Session(proxyAddr string, trickleEvery time.Duration, stop <-chan struct{}) {
	c, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		return
	}
	defer c.Close()
	_, _ = c.Write([]byte{0x05, 0x01, 0x00})
	var m [2]byte
	if _, err := io.ReadFull(c, m[:]); err != nil {
		return
	}
	_, _ = c.Write([]byte{0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0x01, 0xbb})
	var rep [10]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		return
	}
	t := time.NewTicker(trickleEvery)
	defer t.Stop()
	var buf [4]byte
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if _, err := c.Write([]byte("ping")); err != nil {
				return
			}
			if _, err := io.ReadFull(c, buf[:]); err != nil {
				return
			}
		}
	}
}

func makeDeterministicPayload(size int, seed uint64) []byte {
	out := make([]byte, size)
	rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	for i := 0; i+8 <= size; i += 8 {
		binary.LittleEndian.PutUint64(out[i:i+8], rng.Uint64())
	}
	for i := (size / 8) * 8; i < size; i++ {
		out[i] = byte(rng.Uint64())
	}
	return out
}

func waitUntil(t *testing.T, timeout time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for: %s", timeout, desc)
}

func assertNoGoroutineLeak(t *testing.T, baseline int, tolerance int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		runtime.GC()
		if runtime.NumGoroutine() <= baseline+tolerance {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("goroutine leak detected: baseline=%d current=%d (tolerance=%d)", baseline, runtime.NumGoroutine(), tolerance)
}

func readJSONLLog(t *testing.T, path string) []LogRecord {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log %s: %v", path, err)
	}
	var out []LogRecord
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec LogRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("invalid JSONL record %q: %v", line, err)
		}
		out = append(out, rec)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan log %s: %v", path, err)
	}
	return out
}

func readMetricsNDJSON(t *testing.T, path string) []MetricRecord {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read metrics %s: %v", path, err)
	}
	var out []MetricRecord
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec MetricRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("invalid metrics NDJSON line %q: %v", line, err)
		}
		out = append(out, rec)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan metrics %s: %v", path, err)
	}
	return out
}

func testSeed(t *testing.T) int64 {
	t.Helper()
	if s := strings.TrimSpace(os.Getenv("NETSHAPER_TEST_SEED")); s != "" {
		if v, err := strconv.ParseInt(s, 10, 64); err == nil {
			return v
		}
	}
	return 20261121
}
