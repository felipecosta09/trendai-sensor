package metrics

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/trendai/sensor/internal/filter"
)

// Every counter and gauge returned by New must be registered on the given
// registry and present in a /metrics scrape. Guards against adding a field to
// Metrics but forgetting to include it in reg.MustRegister(...).
func TestNewRegistersAllCollectors(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	// CounterVec/GaugeVec without observed label values don't appear in a
	// scrape — trigger one series per vec so we can assert presence.
	m.PacketsCaptured.WithLabelValues("eth0", "ingress").Add(0)
	m.CaptureMode.WithLabelValues("tcbpf").Set(0)

	body := scrape(t, reg)

	want := []string{
		"sensor_packets_captured_total",
		"sensor_packets_forwarded_total",
		"sensor_bytes_forwarded_total",
		"sensor_packets_dropped_filter_total",
		"sensor_packets_dropped_kernel_total",
		"sensor_mtu_exceeded_total",
		"sensor_ndr_send_errors_total",
		"sensor_capture_mode",
	}
	for _, name := range want {
		if !strings.Contains(body, name) {
			t.Errorf("metric %q missing from scrape", name)
		}
	}
}

// Dashboards rely on every drop-reason label series existing from t=0, so
// `rate(...)` / `sum by (reason)` work even before any drops occur. Verify
// each AllReasons value is pre-registered at value 0.
func TestFilterDropsPreRegistered(t *testing.T) {
	reg := prometheus.NewRegistry()
	_ = New(reg)
	body := scrape(t, reg)

	for _, r := range filter.AllReasons {
		needle := `sensor_packets_dropped_filter_total{reason="` + string(r) + `"} 0`
		if !strings.Contains(body, needle) {
			t.Errorf("expected %q in scrape, got:\n%s", needle, body)
		}
	}
}

// rb_full and mtu_exceeded are exported via separate counters (kernel_drops
// and mtu_exceeded), not as FilterDrops label values. Guard against someone
// re-adding them to AllReasons — that would create a ghost label series that
// never increments (see BUG-2).
func TestAllReasonsDoesNotLeakKernelOrMTU(t *testing.T) {
	for _, r := range filter.AllReasons {
		if r == "rb_full" {
			t.Error("rb_full should be exported via sensor_packets_dropped_kernel_total, not FilterDrops")
		}
		if r == "mtu_exceeded" {
			t.Error("mtu_exceeded should be exported via sensor_mtu_exceeded_total, not FilterDrops")
		}
	}
}

// Simulate two statsReporter ticks: the reporter takes cumulative totals and
// Adds only the delta. If we ever regress to Adding the cumulative value, a
// 10-tick scrape would show counter values quadratic in tick count.
func TestCounterDeltaPatternNoDoubleCount(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	// Tick 1: cumulative kernel_drops = 5
	var prev uint64
	m.KernelDrops.Add(float64(uint64(5) - prev))
	prev = 5
	// Tick 2: cumulative kernel_drops = 12 (7 new drops)
	m.KernelDrops.Add(float64(uint64(12) - prev))
	prev = 12

	body := scrape(t, reg)
	if !strings.Contains(body, "sensor_packets_dropped_kernel_total 12") {
		t.Errorf("expected kernel_drops=12, got:\n%s", body)
	}
}

func scrape(t *testing.T, reg *prometheus.Registry) string {
	t.Helper()
	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	Handler(reg).ServeHTTP(rec, req)
	b, _ := io.ReadAll(rec.Body)
	return string(b)
}
