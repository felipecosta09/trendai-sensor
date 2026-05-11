//go:build e2e

// Package e2e contains in-cluster validation tests for the TrendAI sensor.
// These tests require a real Kubernetes cluster — they are NOT run in CI.
// Run locally with:
//
//	make e2e
//
// Prerequisites (see Makefile e2e target comments):
//   - kubectl context pointing at an EKS cluster
//   - helm release deployed with e2e/values-e2e.yaml
//   - prometheus.enabled=true (metrics assertions read /metrics)
package e2e

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	e2eNamespace   = "trendai-e2e"
	e2eRelease     = "trendai-sensor-e2e"
	e2eLabelSel    = "app.kubernetes.io/name=trendai-sensor"
	metricsPort    = "9090"
	podReadyWait   = 60 * time.Second
	watcherSettle  = 5 * time.Second
)

// TestIntraNodeCapture verifies that pod-to-pod traffic on the same node
// is captured and counted in sensor_packets_captured_total.
func TestIntraNodeCapture(t *testing.T) {
	node := mustGetNode(t)

	podA := "e2e-pod-a"
	podB := "e2e-pod-b"
	t.Cleanup(func() { deletePods(t, podA, podB) })
	deletePods(t, podA, podB) // clean up from any previous run

	spawnPod(t, podA, node)
	spawnPod(t, podB, node)
	waitPodsReady(t, podReadyWait, podA, podB)

	podBIP := mustOutput(t, "kubectl", "get", "pod", podB,
		"-o", "jsonpath={.status.podIP}")

	mustRun(t, "kubectl", "exec", podA, "--", "ping", "-c", "20", podBIP)

	sensor := sensorPodOnNode(t, node)
	metrics := mustOutput(t, "kubectl", "-n", e2eNamespace, "exec", sensor,
		"--", "wget", "-qO-", "http://localhost:"+metricsPort+"/metrics")

	if !strings.Contains(metrics, "sensor_packets_captured_total") {
		t.Fatalf("sensor_packets_captured_total not found in metrics output")
	}

	// At least one intra-node interface (eni*, veth*, etc.) must have a non-zero count.
	found := false
	for _, line := range strings.Split(metrics, "\n") {
		if !strings.HasPrefix(line, "sensor_packets_captured_total") {
			continue
		}
		if strings.HasSuffix(strings.TrimSpace(line), "0") {
			continue
		}
		found = true
		t.Logf("capture counter: %s", line)
		break
	}
	if !found {
		t.Fatal("expected non-zero sensor_packets_captured_total for at least one pod-veth interface")
	}

	// Confirm the watcher log line appeared.
	logs := mustOutput(t, "kubectl", "-n", e2eNamespace, "logs", sensor)
	if !strings.Contains(logs, "pod veth appeared") {
		t.Error("expected 'pod veth appeared, attaching' in sensor logs")
	}
}

// TestDynamicAttach starts a new pod after the sensor is already running and
// confirms the watcher attaches it dynamically.
func TestDynamicAttach(t *testing.T) {
	node := mustGetNode(t)
	podC := "e2e-pod-c"
	t.Cleanup(func() { deletePods(t, podC) })
	deletePods(t, podC)

	spawnPod(t, podC, node)
	waitPodsReady(t, podReadyWait, podC)
	time.Sleep(watcherSettle)

	sensor := sensorPodOnNode(t, node)
	logs := mustOutput(t, "kubectl", "-n", e2eNamespace, "logs", sensor)
	if !strings.Contains(logs, "pod veth appeared") {
		t.Error("expected 'pod veth appeared, attaching' in sensor logs after dynamic pod start")
	}
}

// TestDynamicDetach deletes a pod and confirms the watcher detaches cleanly
// with no new errors.
func TestDynamicDetach(t *testing.T) {
	node := mustGetNode(t)
	podD := "e2e-pod-d"
	t.Cleanup(func() { deletePods(t, podD) })
	deletePods(t, podD)

	spawnPod(t, podD, node)
	waitPodsReady(t, podReadyWait, podD)
	time.Sleep(watcherSettle)

	mustRun(t, "kubectl", "delete", "pod", podD)
	time.Sleep(watcherSettle)

	sensor := sensorPodOnNode(t, node)
	logs := mustOutput(t, "kubectl", "-n", e2eNamespace, "logs", sensor)
	if !strings.Contains(logs, "pod veth removed") {
		t.Error("expected 'pod veth removed, detaching' in sensor logs after pod delete")
	}
	// No new errors from the detach path.
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, `"level":"ERROR"`) {
			t.Errorf("unexpected ERROR log after pod delete: %s", line)
		}
	}
}

// TestDefaultModeRegression confirms the default (captureIntraNode=false)
// release still captures on eth0 and not on pod-veth interfaces.
func TestDefaultModeRegression(t *testing.T) {
	t.Skip("requires a separate helm release with captureIntraNode=false — deploy manually")
}

// TestGracefulShutdown confirms the sensor pod terminates within the grace
// period after SIGTERM (ctx cancel propagates to capture path within 1 s).
func TestGracefulShutdown(t *testing.T) {
	node := mustGetNode(t)
	sensor := sensorPodOnNode(t, node)

	start := time.Now()
	mustRun(t, "kubectl", "-n", e2eNamespace, "delete", "pod", sensor, "--grace-period=5")

	if d := time.Since(start); d > 8*time.Second {
		t.Errorf("pod termination took %v, expected < 8s with grace-period=5", d)
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func mustGetNode(t *testing.T) string {
	t.Helper()
	return mustOutput(t, "kubectl", "get", "nodes",
		"-o", "jsonpath={.items[0].metadata.name}")
}

func sensorPodOnNode(t *testing.T, node string) string {
	t.Helper()
	return mustOutput(t, "kubectl", "-n", e2eNamespace,
		"get", "pod",
		"-l", e2eLabelSel,
		"--field-selector", "spec.nodeName="+node,
		"-o", "jsonpath={.items[0].metadata.name}")
}

func spawnPod(t *testing.T, name, node string) {
	t.Helper()
	spec := fmt.Sprintf(
		`{"spec":{"nodeName":%q,"containers":[{"name":%q,"image":"alpine","command":["sleep","3600"]}]}}`,
		node, name)
	mustRun(t, "kubectl", "run", name,
		"--image=alpine",
		"--restart=Never",
		"--overrides="+spec)
}

func waitPodsReady(t *testing.T, timeout time.Duration, names ...string) {
	t.Helper()
	args := append([]string{"wait"}, names...)
	args = append(args, "--for=condition=Ready",
		"--timeout="+timeout.String())
	mustRun(t, append([]string{"kubectl"}, args...)...)
}

func deletePods(t *testing.T, names ...string) {
	t.Helper()
	args := append([]string{"kubectl", "delete", "pod", "--ignore-not-found"}, names...)
	_ = exec.Command(args[0], args[1:]...).Run()
}

func mustRun(t *testing.T, args ...string) {
	t.Helper()
	out, err := exec.CommandContext(context.Background(), args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func mustOutput(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.CommandContext(context.Background(), args[0], args[1:]...).Output()
	if err != nil {
		t.Fatalf("%s: %v", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out))
}
