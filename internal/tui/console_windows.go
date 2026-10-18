//go:build windows

package tui

import (
	"os"

	"golang.org/x/sys/windows"
)

// SetupConsole enables colours on a Windows console (see setupConsole).
func SetupConsole(out *os.File) func() { return setupConsole(out) }

// setupConsole enables ANSI escape sequences and UTF-8 output on the Windows
// console and returns a function that restores the previous state.
func setupConsole(out *os.File) func() {
	h := windows.Handle(out.Fd())
	var mode uint32
	restoreMode := func() {}
	if windows.GetConsoleMode(h, &mode) == nil {
		if windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) == nil {
			restoreMode = func() { windows.SetConsoleMode(h, mode) }
		}
	}
	cp, err := windows.GetConsoleOutputCP()
	if err == nil && cp != 65001 {
		windows.SetConsoleOutputCP(65001)
	}
	return func() {
		restoreMode()
		if err == nil && cp != 65001 {
			windows.SetConsoleOutputCP(cp)
		}
	}
}
