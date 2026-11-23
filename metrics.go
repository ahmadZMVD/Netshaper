package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	metricsSchemaVersion = "netshaper.metrics.v6"
	metricsChannelCap    = 1024
	metricsBufSize       = 16 * 1024
	metricsFlushCadence  = 2 * time.Second
)

// MetricRecord is a single structured NDJSON telemetry frame emitted on the orthogonal metrics stream.
// Kept strictly separate from human-facing console output and supervisor EventLogger history.
type MetricRecord struct {
	Schema    string         `json:"schema"`
	Timestamp string         `json:"ts"`
	SessionID string         `json:"session_id"`
	Stream    string         `json:"stream"` // "tunnel" | "conn" | "api_guard" | "net_hygiene" | "pool"
	Data      map[string]any `json:"data"`
}

// ConnMetric captures per-connection lifecycle telemetry emitted on stream="conn".
type ConnMetric struct {
	TunnelID        string  `json:"tunnel_id"`
	UpstreamAddr    string  `json:"upstream_addr"`
	QueueWaitMS     float64 `json:"queue_wait_ms"`
	DialPaceMS      float64 `json:"dial_pace_ms"`
	DialRTTMS       float64 `json:"dial_rtt_ms"`
	ActiveMS        float64 `json:"active_ms"`
	BytesUp         uint64  `json:"bytes_up"`
	BytesDown       uint64  `json:"bytes_down"`
	CloseReason     string  `json:"close_reason"` // half_close_clean | pressure_idle_reap | idle_reap | drain_timeout | dial_fail | queue_timeout | queue_full | abrupt_error | shutdown
	PressureReaped  bool    `json:"pressure_reaped"`
	CopyBufferBytes int     `json:"copy_buffer_bytes"`
}

// MetricsEmitter writes orthogonal structured NDJSON metrics to a dedicated append-only file.
// Like EventLogger, ch is never closed; shutdown drains cleanly via quitCh without panic risk.
type MetricsEmitter struct {
	sessionID string
	path      string
	file      *os.File
	ch        chan MetricRecord
	quitCh    chan struct{}
	done      chan struct{}
	closed    atomic.Bool
	emitted   atomic.Uint64
	dropped   atomic.Uint64
	closeOnce sync.Once
}

// NewMetricsEmitter opens a dedicated NDJSON metrics file with O_CREATE|O_WRONLY|O_APPEND.
func NewMetricsEmitter(path, sessionID string) (*MetricsEmitter, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open metrics ndjson %q: %w", path, err)
	}
	if sessionID == "" {
		sessionID = fmt.Sprintf("pid%d-%d", os.Getpid(), time.Now().UTC().UnixNano())
	}
	m := &MetricsEmitter{
		sessionID: sessionID,
		path:      path,
		file:      f,
		ch:        make(chan MetricRecord, metricsChannelCap),
		quitCh:    make(chan struct{}),
		done:      make(chan struct{}),
	}
	go m.writerLoop()
	return m, nil
}

// Emit enqueues a structured NDJSON record without ever blocking the data plane.
func (m *MetricsEmitter) Emit(stream string, data map[string]any) {
	if m == nil || m.closed.Load() {
		return
	}
	rec := MetricRecord{
		Schema:    metricsSchemaVersion,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		SessionID: m.sessionID,
		Stream:    stream,
		Data:      data,
	}
	select {
	case <-m.quitCh:
		return
	default:
	}
	select {
	case m.ch <- rec:
		m.emitted.Add(1)
	case <-m.quitCh:
		return
	default:
		m.dropped.Add(1)
	}
}

// EmitConn records one completed client connection lifecycle frame on stream="conn".
func (m *MetricsEmitter) EmitConn(cm ConnMetric) {
	if m == nil || m.closed.Load() {
		return
	}
	m.Emit("conn", map[string]any{
		"tunnel_id":         cm.TunnelID,
		"upstream_addr":     cm.UpstreamAddr,
		"queue_wait_ms":     round2(cm.QueueWaitMS),
		"dial_pace_ms":      round2(cm.DialPaceMS),
		"dial_rtt_ms":       round2(cm.DialRTTMS),
		"active_ms":         round2(cm.ActiveMS),
		"bytes_up":          cm.BytesUp,
		"bytes_down":        cm.BytesDown,
		"close_reason":      cm.CloseReason,
		"pressure_reaped":   cm.PressureReaped,
		"copy_buffer_bytes": cm.CopyBufferBytes,
	})
}

// Stats returns emitted and dropped NDJSON metric frame counts.
func (m *MetricsEmitter) Stats() (emitted uint64, dropped uint64) {
	if m == nil {
		return 0, 0
	}
	return m.emitted.Load(), m.dropped.Load()
}

func (m *MetricsEmitter) writerLoop() {
	defer close(m.done)
	bw := bufio.NewWriterSize(m.file, metricsBufSize)
	ticker := time.NewTicker(metricsFlushCadence)
	defer ticker.Stop()

	writeRec := func(rec MetricRecord) {
		b, err := json.Marshal(rec)
		if err != nil {
			return
		}
		_, _ = bw.Write(b)
		_ = bw.WriteByte('\n')
	}

	for {
		select {
		case rec := <-m.ch:
			writeRec(rec)
		case <-ticker.C:
			_ = bw.Flush()
		case <-m.quitCh:
			for {
				select {
				case rec := <-m.ch:
					writeRec(rec)
				default:
					_ = bw.Flush()
					_ = m.file.Sync()
					_ = m.file.Close()
					return
				}
			}
		}
	}
}

// Close flushes, syncs, and closes the NDJSON metrics stream safely.
func (m *MetricsEmitter) Close() error {
	if m == nil {
		return nil
	}
	m.closeOnce.Do(func() {
		m.closed.Store(true)
		close(m.quitCh)
		<-m.done
	})
	return nil
}
