package health

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func do(t *testing.T, h http.Handler, path string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestHealthzAlwaysOK(t *testing.T) {
	// Even before MarkReady, /healthz is liveness — must always return 200
	// so kubelet doesn't restart the pod while we're still attaching eBPF.
	s := New(30 * time.Second)
	if code := do(t, s.Handler(), "/healthz"); code != http.StatusOK {
		t.Errorf("/healthz = %d, want 200", code)
	}
}

func TestReadyzBeforeMarkReady(t *testing.T) {
	s := New(30 * time.Second)
	if code := do(t, s.Handler(), "/readyz"); code != http.StatusServiceUnavailable {
		t.Errorf("/readyz before MarkReady = %d, want 503", code)
	}
}

func TestReadyzReadyWithoutTraffic(t *testing.T) {
	// Ready with no Observe calls means capAge and fwdAge are both huge (since
	// lastCapture/lastForward default to 0). That hits the "idle node" branch
	// (capAge > staleAfter AND fwdAge > staleAfter) — stay ready.
	s := New(30 * time.Second)
	s.MarkReady()
	if code := do(t, s.Handler(), "/readyz"); code != http.StatusOK {
		t.Errorf("/readyz idle = %d, want 200", code)
	}
}

func TestReadyzStuckForwarder(t *testing.T) {
	// Recent capture but stale forward = broken: /readyz must return 503.
	s := New(100 * time.Millisecond)
	s.MarkReady()
	s.ObserveCapture(time.Now())                     // fresh
	s.ObserveForward(time.Now().Add(-1 * time.Hour)) // very stale
	if code := do(t, s.Handler(), "/readyz"); code != http.StatusServiceUnavailable {
		t.Errorf("/readyz stuck = %d, want 503", code)
	}
}

func TestReadyzHealthyPair(t *testing.T) {
	s := New(30 * time.Second)
	s.MarkReady()
	s.ObserveCapture(time.Now())
	s.ObserveForward(time.Now())
	if code := do(t, s.Handler(), "/readyz"); code != http.StatusOK {
		t.Errorf("/readyz healthy = %d, want 200", code)
	}
}

func TestObserveRaceSafety(t *testing.T) {
	// `go test -race` catches unsynchronized writes to lastCapture/lastForward.
	s := New(30 * time.Second)
	s.MarkReady()
	h := s.Handler()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					now := time.Now()
					s.ObserveCapture(now)
					s.ObserveForward(now)
				}
			}
		}()
	}
	for i := 0; i < 100; i++ {
		do(t, h, "/readyz")
	}
	close(stop)
	wg.Wait()
}
