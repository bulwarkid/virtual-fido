package fido_client

import "testing"

func TestPINRetriesExhausted(t *testing.T) {
	client := &DefaultFIDOClient{pinRetries: 8}
	for retries := int32(7); retries >= 0; retries-- {
		client.SetPINRetries(retries)
		if got := client.PINRetries(); got != retries {
			t.Fatalf("expected %d retries, got %d", retries, got)
		}
	}
}
