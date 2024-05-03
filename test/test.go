package test

import "testing"

type nillable[A any] interface {
	[]A
}

func Assert(t *testing.T, test bool, msg string) {
	if !test {
		t.Fatalf(msg)
	}
}

func AssertEqual[T comparable](t *testing.T, val1 T, val2 T, msg string) {
	if val1 != val2 {
		t.Fatalf("%v != %v: %s", val1, val2, msg)
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