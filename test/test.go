package test

import "testing"

type nillable[A any] interface {
	[]A
}

func AssertEqual[T comparable](t *testing.T, val1 T, val2 T, msg string) {
	if val1 != val2 {
		t.Fatalf(msg)
	}
}

func AssertNotEqual[T comparable](t *testing.T, val1 T, val2 T, msg string) {
	if val1 == val2 {
		t.Fatalf(msg)
	}
}

func AssertNotNil[A any, T nillable[A]](t *testing.T, val T, msg string) {
	if val == nil {
		t.Fatalf(msg)
	}
}