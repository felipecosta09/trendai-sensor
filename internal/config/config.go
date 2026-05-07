// Package config loads sensor configuration from environment variables.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	NDRAddr     string
	VNI         uint32
	NDRMTU      int
	CaptureMode string
	LogLevel    string
	MetricsAddr string
	HealthAddr  string
}

func Load() (Config, error) {
	c := Config{
		NDRAddr:     getenv("SENSOR", "10.0.0.1"),
		CaptureMode: getenv("CAPTURE_MODE", "auto"),
		LogLevel:    strings.ToLower(getenv("LOG_LEVEL", "info")),
		MetricsAddr: getenv("METRICS_ADDR", ":9090"),
		HealthAddr:  getenv("HEALTH_ADDR", ":8080"),
	}

	vniStr := getenv("VNI", "0")
	vni, err := strconv.ParseUint(vniStr, 16, 32)
	if err != nil {
		return c, fmt.Errorf("VNI %q not hex: %w", vniStr, err)
	}
	if vni&0xff000000 != 0 {
		return c, fmt.Errorf("VNI %#x exceeds 24 bits", vni)
	}
	c.VNI = uint32(vni)

	mtuStr := getenv("NDR_MTU", "1500")
	mtu, err := strconv.Atoi(mtuStr)
	if err != nil || mtu < 100 || mtu > 65535 {
		return c, fmt.Errorf("NDR_MTU %q invalid", mtuStr)
	}
	c.NDRMTU = mtu

	switch c.CaptureMode {
	case "", "auto", "tcbpf", "afpacket":
	default:
		return c, fmt.Errorf("CAPTURE_MODE %q invalid", c.CaptureMode)
	}
	return c, nil
}

func getenv(k, def string) string {
	if v, ok := os.LookupEnv(k); ok {
		return v
	}
	return def
}
