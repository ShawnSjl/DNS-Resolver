package blocklist

import "testing"

func TestExactMatch(t *testing.T) {
	b := New([]string{"example.com"})
	if !b.Contains("example.com") {
		t.Fatal("expected exact domain to be blocked")
	}
	if b.Contains("badexample.com") {
		t.Fatal("did not expect partial exact match")
	}
}

func TestWildcardMatch(t *testing.T) {
	b := New([]string{"*.example.com"})
	if !b.Contains("ads.example.com") {
		t.Fatal("expected one-label wildcard match")
	}
	if !b.Contains("a.b.example.com") {
		t.Fatal("expected multi-label wildcard match")
	}
	if b.Contains("example.com") {
		t.Fatal("wildcard should not match bare domain")
	}
}

func TestSuffixMatch(t *testing.T) {
	b := New([]string{".example.com"})
	if !b.Contains("ads.example.com") {
		t.Fatal("expected suffix match")
	}
	if b.Contains("badexample.com") {
		t.Fatal("suffix match should honor label boundary")
	}
}

func TestCaseInsensitive(t *testing.T) {
	b := New([]string{"Example.COM"})
	if !b.Contains("EXAMPLE.com.") {
		t.Fatal("expected case-insensitive match")
	}
}

func TestUnblock(t *testing.T) {
	b := New([]string{"example.com"})
	b.Remove("example.com")
	if b.Contains("example.com") {
		t.Fatal("expected domain to be removed")
	}
}
