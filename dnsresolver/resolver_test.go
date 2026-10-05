package dnsresolver

import (
	"reflect"
	"testing"
)

func TestHappyEyeballsOrderStartsIPv6ThenIPv4(t *testing.T) {
	got := happyEyeballsOrder([]string{"192.0.2.1", "2001:db8::1", "192.0.2.2", "2001:db8::2"})
	want := []string{"2001:db8::1", "192.0.2.1", "2001:db8::2", "192.0.2.2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("happyEyeballsOrder() = %v, want %v", got, want)
	}
}

func TestNormalizeIPVersionPreference(t *testing.T) {
	tests := map[string]string{
		"":       "",
		"auto":   "",
		" AUTO ": "",
		"4":      "4",
		"6":      "6",
		"5":      "",
	}
	for input, want := range tests {
		if got := normalizeIPVersionPreference(input); got != want {
			t.Errorf("normalizeIPVersionPreference(%q) = %q, want %q", input, got, want)
		}
	}
}
