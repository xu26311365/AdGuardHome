package rewrite

import (
	"fmt"
	"net"
	"strings"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/miekg/dns"
)

// Item is a single DNS rewrite record.
type Item struct {
	// Domain is the domain pattern for which this rewrite should work.
	Domain string `yaml:"domain"`

	// Answer is the IP address, canonical name, or one of the special
	// values: "A" or "AAAA".
	Answer string `yaml:"answer"`

	// Type is the DNS record type: A, AAAA, or CNAME.
	Type uint16 `yaml:"-"`

	// Exception is the flag to create exception rules with Domain special
	// values "A" or "AAAA".
	Exception bool `yaml:"-"`
}

// equal returns true if rw is equal to other.
func (rw *Item) equal(other *Item) (ok bool) {
	if rw == nil {
		return other == nil
	} else if other == nil {
		return false
	}

	return rw.Domain == other.Domain && rw.Answer == other.Answer
}

// toRule converts rw to a filter rule.
func (rw *Item) toRule() (res string) {
	if rw.Exception {
		return fmt.Sprintf("@@||%s^$dnstype=%s,dnsrewrite", rw.Domain, dns.TypeToString[rw.Type])
	}

	return fmt.Sprintf("|%s^$dnsrewrite=NOERROR;%s;%s", rw.Domain, dns.TypeToString[rw.Type], rw.Answer)
}

// Normalize makes sure that rw as a new or decoded entry is normalized
// regarding domain name case, IP length, and so on.
//
// If rw is nil, it returns an error.
func (rw *Item) Normalize() (err error) {
	if rw == nil {
		return errors.Error("nil rewrite entry")
	}

	// TODO(a.garipov): Write a case-agnostic version of strings.HasSuffix and
	// use it in matchDomainWildcard instead of using strings.ToLower
	// everywhere.
	rw.Domain = strings.ToLower(rw.Domain)

	switch rw.Answer {
	case "AAAA":
		rw.Type = dns.TypeAAAA
		rw.Exception = true

		return nil
	case "A":
		rw.Type = dns.TypeA
		rw.Exception = true

		return nil
	default:
		// Go on.
	}

	ip := net.ParseIP(rw.Answer)
	if ip == nil {
		rw.Type = dns.TypeCNAME

		return nil
	}

	ip4 := ip.To4()
	if ip4 != nil {
		rw.Type = dns.TypeA
	} else {
		rw.Type = dns.TypeAAAA
	}

	return nil
}
