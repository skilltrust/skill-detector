package main

import (
	"testing"

	"github.com/velzepooz/skill-detector/pkg/rules"
)

func TestNewRegistryMatchesDefaultRegistry(t *testing.T) {
	got := newRegistry(false).Checksum()
	want := rules.DefaultRegistry().Checksum()
	if got != want {
		t.Fatalf("cmd newRegistry checksum %s != rules.DefaultRegistry %s — a rule group registration is missing in one of them", got, want)
	}
}
