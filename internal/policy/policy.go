// Package policy decides which names the portal is willing to put in a certificate.
package policy

import (
	"fmt"
	"net"
	"strings"
)

// Policy holds the allowed DNS suffixes. Public is the subset that Let's Encrypt
// may be asked for (zones that live in Cloudflare, where the DNS-01 solver works).
type Policy struct {
	Domains       []string
	PublicDomains []string
	IPRanges      []*net.IPNet // allowed IP SANs (internal certs only)
}

// ParseRanges parses a list of CIDRs.
func ParseRanges(cidrs []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(strings.TrimSpace(c))
		if err != nil {
			return nil, fmt.Errorf("bad IP range %q: %w", c, err)
		}
		out = append(out, n)
	}
	return out, nil
}

// SplitHosts separates IP addresses from DNS names.
func SplitHosts(names []string) (dns []string, ips []net.IP) {
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, n)
		}
	}
	return dns, ips
}

// CheckInternal validates names for a certificate signed directly by step-ca:
// DNS names under the allowed domains (no public DNS needed) and IPs in range.
func (p Policy) CheckInternal(names []string) error {
	if len(names) == 0 {
		return fmt.Errorf("at least one name or IP address is required")
	}
	if len(names) > maxNames {
		return fmt.Errorf("too many names (%d, max %d)", len(names), maxNames)
	}
	dns, ips := SplitHosts(names)
	for _, n := range dns {
		if err := p.CheckDNS(n, false); err != nil {
			return err
		}
	}
	for _, ip := range ips {
		ok := false
		for _, r := range p.IPRanges {
			ok = ok || r.Contains(ip)
		}
		if !ok {
			return fmt.Errorf("%s: IP address not in an allowed range", ip)
		}
	}
	return nil
}

const maxNames = 50

// Normalize lower-cases, trims and de-duplicates names, keeping order.
func Normalize(names []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		n = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

// SplitNames accepts names separated by commas, spaces or newlines.
func SplitNames(s string) []string {
	return Normalize(strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' || r == ';'
	}))
}

// CheckACME validates names for a cert-manager (ACME) issuance: DNS names only.
func (p Policy) CheckACME(names []string, public bool) error {
	if len(names) == 0 {
		return fmt.Errorf("at least one DNS name is required")
	}
	if len(names) > maxNames {
		return fmt.Errorf("too many names (%d, max %d)", len(names), maxNames)
	}
	for _, n := range names {
		if net.ParseIP(n) != nil {
			return fmt.Errorf("%s: IP addresses are only allowed on internal certificates", n)
		}
		if err := p.CheckDNS(n, public); err != nil {
			return err
		}
	}
	return nil
}

// CheckDNS validates one DNS name against syntax and the allowed suffixes.
func (p Policy) CheckDNS(name string, public bool) error {
	if err := validHostname(name); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if !underAny(name, p.Domains) {
		return fmt.Errorf("%s: not under an allowed domain (%s)", name, strings.Join(p.Domains, ", "))
	}
	if public && !underAny(name, p.PublicDomains) {
		return fmt.Errorf("%s: public certificates are only available under %s", name, strings.Join(p.PublicDomains, ", "))
	}
	return nil
}

func underAny(name string, suffixes []string) bool {
	name = strings.TrimPrefix(name, "*.")
	for _, s := range suffixes {
		if name == s || strings.HasSuffix(name, "."+s) {
			return true
		}
	}
	return false
}

func validHostname(name string) error {
	if len(name) > 253 {
		return fmt.Errorf("name too long")
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return fmt.Errorf("must be a fully qualified name")
	}
	for i, l := range labels {
		if l == "*" {
			if i != 0 {
				return fmt.Errorf("wildcard only allowed as the leftmost label")
			}
			continue
		}
		if l == "" || len(l) > 63 {
			return fmt.Errorf("invalid label %q", l)
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("label %q can't start or end with '-'", l)
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return fmt.Errorf("invalid character %q", r)
			}
		}
	}
	return nil
}
