//go:build !windows

package tui

import "os"

func setupConsole(*os.File) func() { return func() {} }
