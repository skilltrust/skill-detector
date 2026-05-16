package main

// cliInput adapts a CLI directory path to the scanner.Input interface.
type cliInput struct{ p string }

// Path implements scanner.Input.
func (c cliInput) Path() string { return c.p }
