//go:build !darwin

package main

import "errors"

type unsupportedGuard struct{}

func newLeakGuard(int, string) unsupportedGuard { return unsupportedGuard{} }

func (unsupportedGuard) Supported() error {
	return errors.New("leak protection is implemented only for macOS")
}
func (g unsupportedGuard) Apply(string) error { return g.Supported() }
func (unsupportedGuard) Release() error       { return nil }
