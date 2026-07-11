package shodan

import (
	"bytes"
	"encoding/json"
	"strconv"
)

// CVSS is a CVSS score that Shodan may encode as either a JSON number or a
// string; it unmarshals both to a float64 (0 when null/empty/unparseable).
type CVSS float64

// UnmarshalJSON accepts numbers and strings.
func (c *CVSS) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		*c = 0
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		if s == "" {
			*c = 0
			return nil
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			*c = 0
			return nil
		}
		*c = CVSS(f)
		return nil
	}
	var f float64
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	*c = CVSS(f)
	return nil
}

// Float returns the score as a plain float64.
func (c CVSS) Float() float64 { return float64(c) }

// HostResponse is the subset of GET /shodan/host/{ip} we consume. The full raw
// body is persisted separately so nothing is lost.
type HostResponse struct {
	IP          string    `json:"ip_str"`
	Ports       []int     `json:"ports"`
	Hostnames   []string  `json:"hostnames"`
	Domains     []string  `json:"domains"`
	Org         string    `json:"org"`
	ISP         string    `json:"isp"`
	OS          string    `json:"os"`
	ASN         string    `json:"asn"`
	Tags        []string  `json:"tags"`
	Vulns       []string  `json:"vulns"`
	CountryCode string    `json:"country_code"`
	City        string    `json:"city"`
	LastUpdate  string    `json:"last_update"`
	Data        []Service `json:"data"`
}

// Service is a single banner/service observation within a host response.
type Service struct {
	Port      int             `json:"port"`
	Transport string          `json:"transport"`
	Product   string          `json:"product"`
	Version   string          `json:"version"`
	CPE       []string        `json:"cpe"`
	Data      string          `json:"data"`
	Timestamp string          `json:"timestamp"`
	Hostnames []string        `json:"hostnames"`
	Tags      []string        `json:"tags"`
	Shodan    ShodanMeta      `json:"_shodan"`
	Opts      ServiceOpts     `json:"opts"`
	Vulns     map[string]Vuln `json:"vulns"`
	SSL       *SSL            `json:"ssl"`
	SMB       *SMB            `json:"smb"`
	MQTT      json.RawMessage `json:"mqtt"`
}

// ShodanMeta carries the Shodan module that produced a banner.
type ShodanMeta struct {
	Module  string `json:"module"`
	ID      string `json:"id"`
	Crawler string `json:"crawler"`
}

// ServiceOpts holds optional per-service extras such as screenshots.
type ServiceOpts struct {
	Screenshot *Screenshot `json:"screenshot"`
}

// Screenshot is a captured screen image (base64 JPEG) plus classifier labels.
type Screenshot struct {
	Data   string   `json:"data"`
	MIME   string   `json:"mime"`
	Labels []string `json:"labels"`
}

// Vuln is a per-service vulnerability detail.
type Vuln struct {
	Verified   bool     `json:"verified"`
	CVSS       CVSS     `json:"cvss"`
	CVSSv2     CVSS     `json:"cvss_v2"`
	References []string `json:"references"`
	Summary    string   `json:"summary"`
}

// SSL captures TLS/cert observations.
type SSL struct {
	Versions []string  `json:"versions"`
	Cert     SSLCert   `json:"cert"`
	Cipher   SSLCipher `json:"cipher"`
}

// SSLCert is the subset of certificate detail we evaluate.
type SSLCert struct {
	Expired    bool           `json:"expired"`
	Expires    string         `json:"expires"`
	Issued     string         `json:"issued"`
	Subject    map[string]any `json:"subject"`
	Issuer     map[string]any `json:"issuer"`
	SelfSigned *bool          `json:"-"`
}

// SSLCipher describes the negotiated cipher.
type SSLCipher struct {
	Version string `json:"version"`
	Name    string `json:"name"`
	Bits    int    `json:"bits"`
}

// SMB describes an observed SMB service.
type SMB struct {
	Anonymous bool       `json:"anonymous"`
	Shares    []SMBShare `json:"shares"`
}

// SMBShare is a single exposed SMB share.
type SMBShare struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Comment string `json:"comments"`
}

// DNSResolveResponse maps hostname -> IP for GET /dns/resolve.
type DNSResolveResponse map[string]string

// DNSReverseResponse maps IP -> hostnames for GET /dns/reverse.
type DNSReverseResponse map[string][]string

// DomainResponse is the subset of GET /dns/domain/{domain} we consume.
type DomainResponse struct {
	Domain     string      `json:"domain"`
	Subdomains []string    `json:"subdomains"`
	Data       []DomainDNS `json:"data"`
}

// DomainDNS is a single DNS record from a domain enumeration.
type DomainDNS struct {
	Subdomain string `json:"subdomain"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	LastSeen  string `json:"last_seen"`
}

// APIInfoResponse is GET /api-info for a single key.
type APIInfoResponse struct {
	QueryCredits int    `json:"query_credits"`
	ScanCredits  int    `json:"scan_credits"`
	Plan         string `json:"plan"`
	HTTPS        bool   `json:"https"`
	Unlocked     bool   `json:"unlocked"`
}

// ScanSubmitResponse is POST /shodan/scan.
type ScanSubmitResponse struct {
	ID          string `json:"id"`
	Count       int    `json:"count"`
	CreditsLeft int    `json:"credits_left"`
}

// ScanStatusResponse is GET /shodan/scan/{id}.
type ScanStatusResponse struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Count  int    `json:"count"`
}
