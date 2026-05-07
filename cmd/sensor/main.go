package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/trendai/sensor/internal/capture"
	"github.com/trendai/sensor/internal/config"
	"github.com/trendai/sensor/internal/filter"
	"github.com/trendai/sensor/internal/forward"
	"github.com/trendai/sensor/internal/health"
	"github.com/trendai/sensor/internal/iface"
	"github.com/trendai/sensor/internal/metrics"
)

func main() {
	os.Exit(run())
}

func run() int {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config", "err", err)
		return 2
	}
	setupLogger(cfg.LogLevel)
	slog.Info("starting", "ndr", cfg.NDRAddr, "vni", cfg.VNI, "mtu", cfg.NDRMTU, "mode", cfg.CaptureMode)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	hs := health.New(30 * time.Second)

	// HTTP servers (metrics + health).
	go serve(ctx, cfg.MetricsAddr, metrics.Handler(reg))
	go serve(ctx, cfg.HealthAddr, hs.Handler())

	// Pick capture mode.
	mode, err := capture.Pick(cfg.CaptureMode)
	if err != nil {
		slog.Error("capture pick", "err", err)
		return 1
	}
	slog.Info("capture mode selected", "mode", mode)
	m.CaptureMode.WithLabelValues(mode).Set(1)

	// Build capturer.
	var cap capture.Capturer
	switch mode {
	case "tcbpf":
		t, err := capture.NewTCBPF()
		if err != nil {
			slog.Error("tcbpf init", "err", err)
			return 1
		}
		cap = t
	case "afpacket":
		cap = capture.NewAFPacket(filter.Default())
	default:
		// Pick() currently only returns "tcbpf" or "afpacket", but guard
		// against a future mode being added without the switch being updated
		// — without this, the `defer cap.Close()` below would panic on nil.
		slog.Error("unknown capture mode", "mode", mode)
		return 1
	}
	defer cap.Close()

	// Interfaces.
	ifaces, err := iface.List()
	if err != nil || len(ifaces) == 0 {
		slog.Error("no capture interfaces", "err", err, "found", ifaces)
		return 1
	}
	slog.Info("interfaces", "list", ifaces)

	// Forwarder.
	fwd, err := forward.New(cfg.NDRAddr, cfg.VNI, cfg.NDRMTU)
	if err != nil {
		slog.Error("forwarder", "err", err)
		return 1
	}
	defer fwd.Close()

	packets, err := cap.Start(ctx, ifaces)
	if err != nil {
		slog.Error("capture start", "err", err)
		return 1
	}
	hs.MarkReady()

	go statsReporter(ctx, cap, fwd, m)

	for pkt := range packets {
		hs.ObserveCapture(time.Now())
		m.PacketsCaptured.WithLabelValues(pkt.Iface, pkt.Direction.String()).Inc()
		n := fwd.Send(pkt.Data)
		if n == 0 {
			// Send failed or MTU exceeded — detailed counter already bumped.
			continue
		}
		m.PacketsForwarded.Inc()
		m.BytesForwarded.Add(float64(n + forward.VXLANOverhead))
		hs.ObserveForward(time.Now())
	}
	slog.Info("capture channel closed, exiting")
	return 0
}

func setupLogger(level string) {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})
	slog.SetDefault(slog.New(h))
}

func serve(ctx context.Context, addr string, h http.Handler) {
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("http server", "addr", addr, "err", err)
	}
}

// statsReporter logs aggregate counters every 10 s and flushes filter-drop
// counters from the capturer into Prometheus.
//
// Both cap.Stats() and fwd.Stats() return cumulative totals. Prometheus
// counters are themselves cumulative, so we must Add only the delta each
// tick — Adding the running total every 10 s inflates the counter
// exponentially.
func statsReporter(ctx context.Context, cap capture.Capturer, fwd *forward.Forwarder, m *metrics.Metrics) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	var (
		prevCaptured, prevSent, prevBytes     uint64
		prevKernelDrops, prevMTU, prevSendErr uint64
		prevFilterDrops                       = map[string]uint64{}
	)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cs := cap.Stats()
			fs := fwd.Stats()

			m.KernelDrops.Add(float64(cs.KernelDrops - prevKernelDrops))
			prevKernelDrops = cs.KernelDrops
			for reason, v := range cs.FilterDrops {
				m.FilterDrops.WithLabelValues(reason).Add(float64(v - prevFilterDrops[reason]))
				prevFilterDrops[reason] = v
			}
			m.MTUExceeded.Add(float64(fs.MTUExceeded - prevMTU))
			prevMTU = fs.MTUExceeded
			m.SendErrors.Add(float64(fs.SendErrors - prevSendErr))
			prevSendErr = fs.SendErrors

			capDelta := cs.CapturedPackets - prevCaptured
			sentDelta := fs.Sent - prevSent
			bytesDelta := fs.BytesOut - prevBytes
			prevCaptured, prevSent, prevBytes = cs.CapturedPackets, fs.Sent, fs.BytesOut

			slog.Info("tick",
				"pps_in", capDelta/10,
				"pps_out", sentDelta/10,
				"mbps_out", (bytesDelta*8)/1_000_000/10,
				"kernel_drops", cs.KernelDrops,
				"mtu_exceeded", fs.MTUExceeded,
				"send_errors", fs.SendErrors,
			)
		}
	}
}
