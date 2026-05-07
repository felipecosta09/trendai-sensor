// Package metrics exposes Prometheus counters for the sensor. Labels are
// intentionally low-cardinality (iface, direction, reason) so cardinality
// stays bounded regardless of traffic shape.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/trendai/sensor/internal/filter"
)

type Metrics struct {
	PacketsCaptured  *prometheus.CounterVec
	PacketsForwarded prometheus.Counter
	BytesForwarded   prometheus.Counter
	FilterDrops      *prometheus.CounterVec
	KernelDrops      prometheus.Counter
	MTUExceeded      prometheus.Counter
	SendErrors       prometheus.Counter
	CaptureMode      *prometheus.GaugeVec
}

// New registers all counters on the default registry and returns the struct.
// Pre-registers label series for DropReasons so PromQL queries work from t=0.
func New(reg *prometheus.Registry) *Metrics {
	m := &Metrics{
		PacketsCaptured: prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "sensor_packets_captured_total", Help: "Packets delivered from capture layer."},
			[]string{"iface", "direction"},
		),
		PacketsForwarded: prometheus.NewCounter(
			prometheus.CounterOpts{Name: "sensor_packets_forwarded_total", Help: "Packets successfully sent to the NDR."},
		),
		BytesForwarded: prometheus.NewCounter(
			prometheus.CounterOpts{Name: "sensor_bytes_forwarded_total", Help: "Wire bytes sent to the NDR (VXLAN encapsulated)."},
		),
		FilterDrops: prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "sensor_packets_dropped_filter_total", Help: "Packets dropped by filter, by reason."},
			[]string{"reason"},
		),
		KernelDrops: prometheus.NewCounter(
			prometheus.CounterOpts{Name: "sensor_packets_dropped_kernel_total", Help: "Packets dropped by the kernel capture layer (ringbuf full, AF_PACKET drops)."},
		),
		MTUExceeded: prometheus.NewCounter(
			prometheus.CounterOpts{Name: "sensor_mtu_exceeded_total", Help: "Packets dropped because inner+VXLAN > NDR MTU."},
		),
		SendErrors: prometheus.NewCounter(
			prometheus.CounterOpts{Name: "sensor_ndr_send_errors_total", Help: "Errors sending to the NDR appliance."},
		),
		CaptureMode: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{Name: "sensor_capture_mode", Help: "1 for the active capture mode, 0 otherwise."},
			[]string{"mode"},
		),
	}
	reg.MustRegister(
		m.PacketsCaptured, m.PacketsForwarded, m.BytesForwarded,
		m.FilterDrops, m.KernelDrops, m.MTUExceeded, m.SendErrors, m.CaptureMode,
	)
	for _, r := range filter.AllReasons {
		m.FilterDrops.WithLabelValues(string(r)).Add(0)
	}
	return m
}

// Handler returns an http.Handler serving /metrics.
func Handler(reg *prometheus.Registry) http.Handler {
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg})
}
