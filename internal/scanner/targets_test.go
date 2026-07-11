package scanner

import "testing"

func TestExpandCIDR(t *testing.T) {
	cases := []struct {
		name     string
		cidr     string
		max      int
		wantLen  int
		wantErr  bool
		contains string
	}{
		{"slash30", "192.168.1.0/30", 256, 4, false, "192.168.1.0"},
		{"slash24", "10.0.0.0/24", 256, 256, false, "10.0.0.255"},
		{"too_big", "10.0.0.0/16", 256, 0, true, ""},
		{"single32", "8.8.8.8/32", 256, 1, false, "8.8.8.8"},
		{"masked_input", "10.0.0.5/30", 256, 4, false, "10.0.0.4"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := expandCIDR(c.cidr, c.max)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error for %s", c.cidr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != c.wantLen {
				t.Fatalf("got %d hosts, want %d", len(got), c.wantLen)
			}
			if c.contains != "" {
				found := false
				for _, ip := range got {
					if ip == c.contains {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("expected %s in expansion of %s", c.contains, c.cidr)
				}
			}
		})
	}
}

func TestExpandCIDR_v6Cap(t *testing.T) {
	// A /64 has 2^64 hosts and must be rejected without overflowing.
	if _, err := expandCIDR("2001:db8::/64", 256); err == nil {
		t.Fatal("expected /64 to exceed host cap")
	}
	// A small v6 prefix should expand.
	got, err := expandCIDR("2001:db8::/126", 256)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("expected 4 hosts, got %d", len(got))
	}
}

func TestDedupeSortedIPs(t *testing.T) {
	in := []string{"10.0.0.2", "10.0.0.1", "10.0.0.2", "", "10.0.0.10"}
	got := dedupeSortedIPs(in)
	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.10"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("at %d got %s want %s (%v)", i, got[i], want[i], got)
		}
	}
}
