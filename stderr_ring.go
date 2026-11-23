package main

import (
	"io"
	"sync"
)

const DefaultStderrRingCap = 16 * 1024

// StderrRingBuffer is a concurrency-safe bounded circular buffer that captures trailing child stderr
// while optionally teeing output to an echo writer (e.g., os.Stderr).
type StderrRingBuffer struct {
	mu   sync.Mutex
	buf  []byte
	cap  int
	pos  int
	full bool
	echo io.Writer
}

// NewStderrRingBuffer constructs a ring buffer retaining the most recent capBytes written.
func NewStderrRingBuffer(capBytes int, echo io.Writer) *StderrRingBuffer {
	if capBytes <= 0 {
		capBytes = DefaultStderrRingCap
	}
	return &StderrRingBuffer{
		buf:  make([]byte, capBytes),
		cap:  capBytes,
		echo: echo,
	}
}

// Write appends p into the circular buffer without ever growing unbounded memory.
func (r *StderrRingBuffer) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	r.mu.Lock()
	if len(p) >= r.cap {
		copy(r.buf, p[len(p)-r.cap:])
		r.pos = 0
		r.full = true
	} else {
		rem := r.cap - r.pos
		if len(p) <= rem {
			copy(r.buf[r.pos:], p)
			r.pos += len(p)
			if r.pos == r.cap {
				r.pos = 0
				r.full = true
			}
		} else {
			copy(r.buf[r.pos:], p[:rem])
			copy(r.buf[0:], p[rem:])
			r.pos = len(p) - rem
			r.full = true
		}
	}
	echo := r.echo
	r.mu.Unlock()

	if echo != nil {
		_, _ = echo.Write(p)
	}
	return len(p), nil
}

// Tail returns up to maxBytes of the most recently written stderr bytes in chronological order.
func (r *StderrRingBuffer) Tail(maxBytes int) string {
	if r == nil {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	var data []byte
	if !r.full {
		data = make([]byte, r.pos)
		copy(data, r.buf[:r.pos])
	} else {
		data = make([]byte, r.cap)
		n := copy(data, r.buf[r.pos:])
		copy(data[n:], r.buf[:r.pos])
	}

	if maxBytes > 0 && len(data) > maxBytes {
		data = data[len(data)-maxBytes:]
	}
	return string(data)
}
