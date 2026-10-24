package main

import "testing"

func TestGreeting(t *testing.T) {
	if got, want := greeting("router"), "Hello, router!"; got != want {
		t.Fatalf("greeting() = %q, want %q", got, want)
	}
}
