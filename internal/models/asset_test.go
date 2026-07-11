package models

import "testing"

func TestNormalizeAssetValue(t *testing.T) {
	cases := []struct {
		name    string
		typ     AssetType
		in      string
		want    string
		wantErr bool
	}{
		{"ipv4", AssetIP, "  1.2.3.4 ", "1.2.3.4", false},
		{"ipv6 canonical", AssetIP, "2001:0db8::0001", "2001:db8::1", false},
		{"bad ip", AssetIP, "999.1.1.1", "", true},
		{"cidr masked", AssetCIDR, "10.0.0.5/24", "10.0.0.0/24", false},
		{"bad cidr", AssetCIDR, "10.0.0.0/33", "", true},
		{"fqdn lower", AssetFQDN, "WWW.Example.COM.", "www.example.com", false},
		{"domain", AssetDomain, "example.co.uk", "example.co.uk", false},
		{"bad domain", AssetDomain, "not_a_domain", "", true},
		{"domain no tld", AssetDomain, "localhost", "", true},
		{"empty", AssetIP, "   ", "", true},
		{"fqdn with path", AssetFQDN, "example.com/x", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := NormalizeAssetValue(c.typ, c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", c.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Fatalf("got %q want %q", got, c.want)
			}
		})
	}
}

func TestAssetValidate(t *testing.T) {
	a := &Asset{Type: AssetIP, Value: "1.2.3.4"}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := &Asset{Type: "bogus", Value: "x"}
	if err := bad.Validate(); err == nil {
		t.Fatal("expected invalid type error")
	}
}
