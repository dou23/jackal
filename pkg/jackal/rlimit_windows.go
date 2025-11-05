//go:build windows
// +build windows

package jackal

func setRLimit() error {
	// Windows doesn't support setting file descriptor limits in the same way as Unix systems
	return nil
}
