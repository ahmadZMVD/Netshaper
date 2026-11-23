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
	loggerChannelCap   = 512
	loggerBufSize      = 8192
	loggerFlushCadence = 2 * time.Second
)

// LogRecord represents a single append-only JSONL telemetry record.
type LogRecord struct {
	Timestamp string         `json:"ts"`
	SessionID string         `json:"session_id"`
	Event     string         `json:"event"`
	Fields    map[string]any `json:"fields,omitempty"`
}

// EventLogger provides panic-proof, non-blocking, append-only persistent JSONL telemetry.
// l.ch is intentionally never closed; shutdown is coordinated via quitCh so concurrent
// Log() + Close() calls can never panic with "send on closed channel".
type EventLogger struct {
	sessionID string
	file      *os.File
	ch        chan LogRecord
	quitCh    chan struct{}
	done      chan struct{}
	closed    atomic.Bool
	dropped   atomic.Uint64
	observer  atomic.Pointer[func(LogRecord)]
	closeOnce sync.Once
}

// NewEventLogger opens path with O_CREATE|O_WRONLY|O_APPEND (never truncating history).
func NewEventLogger(path string) (*EventLogger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open append-only log %q: %w", path, err)
	}

	l := &EventLogger{
		sessionID: fmt.Sprintf("pid%d-%d", os.Getpid(), time.Now().UTC().UnixNano()),
		file:      f,
		ch:        make(chan LogRecord, loggerChannelCap),
		quitCh:    make(chan struct{}),
		done:      make(chan struct{}),
	}
	go l.writerLoop()
	return l, nil
}

// SessionID returns the unique identifier for the current NetShaper run.
func (l *EventLogger) SessionID() string {
	if l == nil {
		return ""
	}
	return l.sessionID
}

// DroppedCount returns the number of events dropped due to channel backpressure.
func (l *EventLogger) DroppedCount() uint64 {
	if l == nil {
		return 0
	}
	return l.dropped.Load()
}

// SetObserver installs or clears an optional read-only log observer invoked strictly on writerLoop().
// The datapath Log() call never invokes the observer directly.
func (l *EventLogger) SetObserver(fn func(LogRecord)) {
	if l == nil {
		return
	}
	if fn == nil {
		l.observer.Store(nil)
		return
	}
	l.observer.Store(&fn)
}

// Log enqueues a telemetry event without ever blocking the datapath or panicking during Close().
func (l *EventLogger) Log(event string, fields map[string]any) {
	if l == nil || l.closed.Load() {
		return
	}
	rec := LogRecord{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		SessionID: l.sessionID,
		Event:     event,
		Fields:    fields,
	}
	select {
	case <-l.quitCh:
		return
	default:
	}
	select {
	case l.ch <- rec:
	case <-l.quitCh:
		return
	default:
		l.dropped.Add(1)
	}
}

func (l *EventLogger) writerLoop() {
	defer close(l.done)
	bw := bufio.NewWriterSize(l.file, loggerBufSize)
	ticker := time.NewTicker(loggerFlushCadence)
	defer ticker.Stop()

	writeRecord := func(rec LogRecord) {
		if obs := l.observer.Load(); obs != nil && *obs != nil {
			(*obs)(rec)
		}
		data, err := json.Marshal(rec)
		if err != nil {
			return
		}
		_, _ = bw.Write(data)
		_ = bw.WriteByte('\n')
	}

	for {
		select {
		case rec := <-l.ch:
			writeRecord(rec)
		case <-ticker.C:
			_ = bw.Flush()
		case <-l.quitCh:
			for {
				select {
				case rec := <-l.ch:
					writeRecord(rec)
				default:
					_ = bw.Flush()
					_ = l.file.Sync()
					_ = l.file.Close()
					return
				}
			}
		}
	}
}

// Close signals shutdown via quitCh, drains all queued events, flushes + Sync()s to disk, and closes the file.
func (l *EventLogger) Close() error {
	if l == nil {
		return nil
	}
	l.closeOnce.Do(func() {
		l.closed.Store(true)
		close(l.quitCh)
		<-l.done
	})
	return nil
}
