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

// version is populated at build time via
//
//	-ldflags "-X main.version=<tag>"
//
// and surfaces as sensor_info{version=...}. Left as "dev" when the linker
// flag is missing so a plain `go build` doesn't explode.
var version = "dev"

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
	slog.Info("starting", "version", version, "ndr", cfg.NDRAddr, "vni", cfg.VNI, "mtu", cfg.NDRMTU, "mode", cfg.CaptureMode, "captureIntraNode", cfg.CaptureIntraNode)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	hs := health.New(30 * time.Second)

	// sensor_info always carries version/node so a rolling upgrade is visible
	// via `group by (version) (sensor_info)`. mode and ndr_configured start
	// as placeholders; main fills them in before capture starts, parked mode
	// fills them in before blocking on ctx.
	node := os.Getenv("NODE_NAME")
	ndrConfigured := "false"
	if cfg.NDRAddr != "" {
		ndrConfigured = "true"
	}

	// HTTP servers. Metrics listener is opt-in — the chart sets
	// METRICS_ADDR="" when prometheus.enabled=false so customers without a
	// Prometheus aren't forced to expose an HTTP endpoint from a privileged
	// pod. Counters still exist in-process and still feed the 10-s tick log.
	// Health probes are always on — kubelet needs them for liveness/readiness.
	if cfg.MetricsAddr != "" {
		go serve(ctx, cfg.MetricsAddr, metrics.Handler(reg))
	} else {
		slog.Info("prometheus disabled — /metrics HTTP server not started")
	}
	go serve(ctx, cfg.HealthAddr, hs.Handler())

	// Parked mode: no NDR configured. Pod runs, passes health probes, logs
	// a reminder, but attaches no BPF programs and opens no capture sockets.
	// Operators can deploy the chart on-cluster to validate scheduling / RBAC
	// before an NDR endpoint exists; setting SENSOR_NDR_ADDR and restarting
	// the pod exits this branch and starts real capture. No capture load on
	// the node until the NDR is configured.
	if cfg.NDRAddr == "" {
		m.Info.WithLabelValues(version, node, "parked", ndrConfigured).Set(1)
		hs.MarkReady()
		slog.Warn("ndr not configured — sensor is parked; set SENSOR_NDR_ADDR (helm: sensor.ndrAddr) and redeploy to start capture")
		go parkedReminder(ctx)
		<-ctx.Done()
		slog.Info("parked sensor exiting")
		return 0
	}

	// Pick capture mode.
	mode, err := capture.Pick(cfg.CaptureMode)
	if err != nil {
		slog.Error("capture pick", "err", err)
		return 1
	}
	slog.Info("capture mode selected", "mode", mode)
	m.CaptureMode.WithLabelValues(mode).Set(1)
	m.Info.WithLabelValues(version, node, mode, ndrConfigured).Set(1)

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
	var ifaces []string
	if cfg.CaptureIntraNode {
		ifaces, err = iface.ListPodVeths()
		if err != nil {
			slog.Error("list pod veths", "err", err)
			return 1
		}
		// Empty slice is valid — watcher attaches as pods start.
		slog.Info("intra-node mode: initial pod-veths", "list", ifaces)
	} else {
		ifaces, err = iface.List()
		if err != nil || len(ifaces) == 0 {
			slog.Error("no capture interfaces", "err", err, "found", ifaces)
			return 1
		}
		slog.Info("interfaces", "list", ifaces)
	}

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

	if cfg.CaptureIntraNode {
		go func() {
			if err := iface.Watch(ctx,
				func(name string) {
					if err := cap.Attach(name); err != nil {
						slog.Warn("pod veth appeared, attach failed", "iface", name, "err", err)
					} else {
						slog.Info("pod veth appeared, attaching", "iface", name)
					}
				},
				func(name string) {
					_ = cap.Detach(name)
					slog.Info("pod veth removed, detaching", "iface", name)
				},
			); err != nil {
				slog.Error("iface watcher", "err", err)
			}
		}()
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

// parkedReminder nudges the operator every 10 s that the sensor is idle
// waiting for SENSOR_NDR_ADDR. Runs until ctx is cancelled.
func parkedReminder(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			slog.Warn("ndr not configured — sensor is parked; set SENSOR_NDR_ADDR and redeploy")
		}
	}
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
