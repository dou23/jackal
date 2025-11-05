//go:build !windows
// +build !windows

package jackal

import (
	"runtime"
	"syscall"
)

func setRLimit() error {
	var rLim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLim); err != nil {
		return err
	}
	if rLim.Cur < rLim.Max {
		switch runtime.GOOS {
		case "darwin":
			rLim.Cur = darwinOpenMax
		default:
			rLim.Cur = rLim.Max
		}
		return syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLim)
	}
	return nil
}

// func setRLimit() error {
// 	var rLim syscall.Rlimit
// 	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLim); err != nil {
// 		return err
// 	}
// 	if rLim.Cur < rLim.Max {
// 		switch runtime.GOOS {
// 		case "darwin":
// 			// The max file limit is 10240, even though
// 			// the max returned by Getrlimit is 1<<63-1.
// 			// This is OPEN_MAX in sys/syslimits.h.
// 			rLim.Cur = darwinOpenMax
// 		default:
// 			rLim.Cur = rLim.Max
// 		}
// 		return syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLim)
// 	}
// 	return nil
// }
