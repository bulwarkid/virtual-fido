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

func AssertArrEqual[T comparable](t *testing.T, val1 []T, val2 []T, msg string) {
	equal := true
	if len(val1) != len(val2) {
		equal = false
	} else {
		for i := range val1 {
			if val1[i] != val2[i] {
				equal = false
			}
		}
	}
	if !equal {
		t.Fatalf("%#v != %#v: %s", val1, val2, msg)
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

func AssertContains[T comparable](t *testing.T, arr []T, val T, msg string) {
	for _, val2 := range arr {
		if val2 == val {
			return
		}
	}
	t.Fatalf(msg)
}