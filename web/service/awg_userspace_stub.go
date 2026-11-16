//go:build !linux

package service

import "errors"

const (
	awgUserspaceBinName = "amneziawg-go"
	amneziawgSocketDir  = "/var/run/amneziawg"
	awgProcPrefix       = "awg-go-"
)

var errAwgUserspaceUnsupported = errors.New("amneziawg userspace engine is only supported on Linux")

func awgKernelModuleLoaded() bool         { return false }
func awgKernelModuleIsLegacyV1() bool     { return false }
func awgUserspaceBinPath() string         { return "" }
func awgUserspaceAvailable() bool         { return false }
func awgRuntimeBackendSummary() string    { return "unsupported OS" }
func awgUserspaceLogs() string            { return "" }
func isAwgUserspaceActive(string) bool    { return false }
func awgActiveUserspaceIfaces() []string  { return nil }
func ensureAwgUserspaceInterface(string, int) error { return errAwgUserspaceUnsupported }
func stopAwgUserspaceInterface(string) error        { return nil }
func stopAllAwgUserspaceInterfaces()                {}
func isAwgKernelUnsupportedError(error) bool        { return false }
