// Package health serves /healthz and /readyz. Ready flips to true once the
// capture layer has attached to at least one interface; it flips back to
// false if the forwarder sees no successful send for staleAfter while the
// capture layer is also not receiving (distinguishes "stuck" from "idle").
package health

import (
	"net/http"
	"sync/atomic"
	"time"
)

type Server struct {
	ready       atomic.Bool
	lastForward atomic.Int64 // unix nanos
	lastCapture atomic.Int64 // unix nanos
	staleAfter  time.Duration
}

func New(staleAfter time.Duration) *Server {
	return &Server{staleAfter: staleAfter}
}

func (s *Server) MarkReady()                 { s.ready.Store(true) }
func (s *Server) ObserveForward(t time.Time) { s.lastForward.Store(t.UnixNano()) }
func (s *Server) ObserveCapture(t time.Time) { s.lastCapture.Store(t.UnixNano()) }

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !s.ready.Load() {
			http.Error(w, "not attached", http.StatusServiceUnavailable)
			return
		}
		now := time.Now().UnixNano()
		capAge := time.Duration(now - s.lastCapture.Load())
		fwdAge := time.Duration(now - s.lastForward.Load())
		// "Stuck" = we were receiving packets but not forwarding. If capture
		// is idle too (capAge > staleAfter), consider the node idle, not
		// broken — stay ready.
		if capAge < s.staleAfter && fwdAge > s.staleAfter {
			http.Error(w, "not forwarding", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	return mux
}
