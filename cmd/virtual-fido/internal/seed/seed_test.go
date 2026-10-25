package seed

import "testing"

func TestParseAndHardenDeterministic(t *testing.T) {
	a, err := parseAndHarden("616263") // "abc"
	if err != nil {
		t.Fatalf("parse a: %v", err)
	}
	b, err := parseAndHarden("616263")
	if err != nil {
		t.Fatalf("parse b: %v", err)
	}
	if len(a) != 32 {
		t.Fatalf("want 32 bytes, got %d", len(a))
	}
	if string(a) != string(b) {
		t.Fatalf("expected deterministic output")
	}
	c, err := parseAndHarden("646566") // "def"
	if err != nil {
		t.Fatalf("parse c: %v", err)
	}
	if string(a) == string(c) {
		t.Fatalf("expected different outputs for different seeds")
	}
}
