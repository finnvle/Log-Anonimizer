//go:build !windows

package tui

import "os"

func setupConsole(*os.File) func() { return func() {} }

// SetupConsole enables colours on a Windows console; elsewhere it does nothing.
func SetupConsole(out *os.File) func() { return setupConsole(out) }
