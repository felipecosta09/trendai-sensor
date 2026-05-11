package config

import (
	"os"
	"strings"
	"testing"
)

var allKeys = []string{"SENSOR_NDR_ADDR", "VNI", "NDR_MTU", "CAPTURE_MODE", "LOG_LEVEL", "METRICS_ADDR", "HEALTH_ADDR"}

func TestLoadDefaults(t *testing.T) {
	unsetAll(t)
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := Config{
		NDRAddr:     "",
		VNI:         0,
		NDRMTU:      1500,
		CaptureMode: "auto",
		LogLevel:    "info",
		MetricsAddr: ":9090",
		HealthAddr:  ":8080",
	}
	if c != want {
		t.Errorf("Load() = %+v, want %+v", c, want)
	}
}

func TestLoadVNI(t *testing.T) {
	cases := []struct {
		name    string
		vni     string
		want    uint32
		wantErr string
	}{
		{"zero", "0", 0, ""},
		{"small hex", "1a", 0x1a, ""},
		{"0x prefix", "0x1a", 0x1a, ""},
		{"0x uppercase digits", "0xABCDEF", 0xabcdef, ""},
		{"max 24-bit", "ffffff", 0xffffff, ""},
		{"overflow 24-bit", "1000000", 0, "exceeds 24 bits"},
		{"not hex", "gg", 0, "not hex"},
		{"overflow uint32", "100000000", 0, "not hex"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			unsetAll(t)
			t.Setenv("VNI", tc.vni)
			c, err := Load()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if c.VNI != tc.want {
				t.Errorf("VNI = %#x, want %#x", c.VNI, tc.want)
			}
		})
	}
}

func TestLoadNDRMTU(t *testing.T) {
	cases := []struct {
		name    string
		mtu     string
		want    int
		wantErr bool
	}{
		{"default-ish", "1500", 1500, false},
		{"min boundary", "100", 100, false},
		{"max boundary", "65535", 65535, false},
		{"below min", "99", 0, true},
		{"above max", "65536", 0, true},
		{"non-numeric", "abc", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			unsetAll(t)
			t.Setenv("NDR_MTU", tc.mtu)
			c, err := Load()
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if c.NDRMTU != tc.want {
				t.Errorf("NDRMTU = %d, want %d", c.NDRMTU, tc.want)
			}
		})
	}
}

func TestLoadCaptureMode(t *testing.T) {
	cases := map[string]bool{
		"auto":     true,
		"tcbpf":    true,
		"afpacket": true,
		"xdp":      false,
		"NONSENSE": false,
	}
	for mode, ok := range cases {
		t.Run(mode, func(t *testing.T) {
			unsetAll(t)
			t.Setenv("CAPTURE_MODE", mode)
			_, err := Load()
			if ok && err != nil {
				t.Errorf("mode %q: unexpected error %v", mode, err)
			}
			if !ok && err == nil {
				t.Errorf("mode %q: expected error, got nil", mode)
			}
		})
	}
}

func TestLoadLogLevelLowercased(t *testing.T) {
	unsetAll(t)
	t.Setenv("LOG_LEVEL", "DEBUG")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want debug (lowercased)", c.LogLevel)
	}
}

// unsetAll clears every env var Load() reads and restores prior values on
// test cleanup. t.Setenv doesn't have an inverse, hence the helper.
func unsetAll(t *testing.T) {
	t.Helper()
	for _, k := range allKeys {
		prev, had := os.LookupEnv(k)
		_ = os.Unsetenv(k)
		k := k
		t.Cleanup(func() {
			if had {
				_ = os.Setenv(k, prev)
			} else {
				_ = os.Unsetenv(k)
			}
		})
	}
}
