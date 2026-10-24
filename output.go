package main

import (
	"io"
	"os"
)

// stdout and stderr are indirected so the Bubble Tea interface can suppress
// engine messages while it owns the terminal. Bubble Tea itself writes to the
// real terminal through its own renderer.
var (
	stdout io.Writer = os.Stdout
	stderr io.Writer = os.Stderr
)
