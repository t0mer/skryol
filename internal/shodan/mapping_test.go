package shodan

import (
	"encoding/json"
	"testing"
)

func findingByKey(fs []Finding, kind FindingKind, key string) *Finding {
	for i := range fs {
		if fs[i].Kind == kind && fs[i].Key == key {
			return &fs[i]
		}
	}
	return nil
}

func TestMapHost_PortsAndMeta(t *testing.T) {
	hr := &HostResponse{
		IP:        "1.2.3.4",
		Ports:     []int{22, 443, 443},
		Hostnames: []string{"b.example.com", "a.example.com", "a.example.com"},
		Org:       "Example Org",
		Tags:      []string{"cloud"},
	}
	fs, meta := MapHost(hr)

	if meta.Org != "Example Org" || !meta.Online {
		t.Fatalf("unexpected meta: %+v", meta)
	}
	if len(meta.Hostnames) != 2 {
		t.Fatalf("expected 2 unique hostnames, got %v", meta.Hostnames)
	}
	if meta.Hostnames[0] != "a.example.com" {
		t.Fatalf("hostnames not sorted: %v", meta.Hostnames)
	}
	if findingByKey(fs, KindPort, "22") == nil || findingByKey(fs, KindPort, "443") == nil {
		t.Fatalf("expected port findings for 22 and 443")
	}
	// Duplicate port 443 collapses to one finding.
	count := 0
	for _, f := range fs {
		if f.Kind == KindPort && f.Key == "443" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected single 443 port finding, got %d", count)
	}
}

func TestMapHost_CVEMergeMaxCVSS(t *testing.T) {
	hr := &HostResponse{
		IP:    "1.2.3.4",
		Vulns: []string{"CVE-2020-0001"}, // host-level, no cvss
		Data: []Service{
			{Port: 80, Vulns: map[string]Vuln{
				"CVE-2020-0001": {CVSS: 5.0, Verified: false},
			}},
			{Port: 443, Vulns: map[string]Vuln{
				"CVE-2020-0001": {CVSS: 9.8, Verified: true},
			}},
		},
	}
	fs, _ := MapHost(hr)
	cve := findingByKey(fs, KindCVE, "CVE-2020-0001")
	if cve == nil {
		t.Fatal("expected merged CVE finding")
	}
	if cve.CVSS != 9.8 {
		t.Fatalf("expected max cvss 9.8, got %v", cve.CVSS)
	}
	if cve.Severity != SeverityCritical {
		t.Fatalf("expected critical severity, got %v", cve.Severity)
	}
	if v, _ := cve.Detail["verified"].(bool); !v {
		t.Fatalf("expected verified true after merge")
	}
}

func TestMapHost_Weaknesses(t *testing.T) {
	hr := &HostResponse{
		IP:   "1.2.3.4",
		Tags: []string{"default-password"},
		Data: []Service{
			{Port: 27017, Shodan: ShodanMeta{Module: "mongodb"}},
			{Port: 5900, Shodan: ShodanMeta{Module: "vnc"},
				Opts: ServiceOpts{Screenshot: &Screenshot{Data: "x", Labels: []string{"remote desktop"}}}},
			{Port: 445, SMB: &SMB{Anonymous: true, Shares: []SMBShare{{Name: "PUBLIC"}}}},
		},
	}
	fs, _ := MapHost(hr)

	if findingByKey(fs, KindWeakness, "default_password") == nil {
		t.Error("expected default_password weakness")
	}
	if findingByKey(fs, KindWeakness, "exposed_database:27017") == nil {
		t.Error("expected exposed_database weakness")
	}
	if findingByKey(fs, KindWeakness, "remote_desktop:5900") == nil {
		t.Error("expected remote_desktop weakness")
	}
	shot := findingByKey(fs, KindScreenshot, "screenshot:5900")
	if shot == nil || shot.Severity != SeverityHigh {
		t.Errorf("expected high-severity remote screenshot, got %+v", shot)
	}
	smb := findingByKey(fs, KindSMBShare, "smb:445:PUBLIC")
	if smb == nil || smb.Severity != SeverityHigh {
		t.Errorf("expected high-severity anonymous SMB share, got %+v", smb)
	}
}

func TestCVSS_UnmarshalStringOrNumber(t *testing.T) {
	cases := map[string]float64{
		`{"cvss": 7.5}`:   7.5,
		`{"cvss": "9.8"}`: 9.8,
		`{"cvss": ""}`:    0,
		`{"cvss": null}`:  0,
		`{"cvss": "n/a"}`: 0,
	}
	for in, want := range cases {
		var v struct {
			CVSS CVSS `json:"cvss"`
		}
		if err := json.Unmarshal([]byte(in), &v); err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if v.CVSS.Float() != want {
			t.Errorf("%s: got %v want %v", in, v.CVSS.Float(), want)
		}
	}
}

func TestSeverityFromCVSS(t *testing.T) {
	cases := []struct {
		cvss float64
		want Severity
	}{
		{9.0, SeverityCritical},
		{8.9, SeverityHigh},
		{7.0, SeverityHigh},
		{6.9, SeverityMedium},
		{4.0, SeverityMedium},
		{3.9, SeverityLow},
		{0, SeverityInfo},
	}
	for _, c := range cases {
		if got := severityFromCVSS(c.cvss); got != c.want {
			t.Errorf("cvss %v: got %v want %v", c.cvss, got, c.want)
		}
	}
}
