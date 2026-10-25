package web

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/jwil007/pki-portal/internal/kube"
)

// counters are in-memory and reset on restart, like any Prometheus counter.
type counters struct {
	mu     sync.Mutex
	issued map[[2]string]int // {issuer, mode}
}

func (c *counters) issue(issuer string, mode kube.Mode) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.issued == nil {
		c.issued = map[[2]string]int{}
	}
	c.issued[[2]string{issuer, string(mode)}]++
}

func label(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

// Metrics serves Prometheus text format. It's meant for a separate, cluster-internal port.
func (s *Server) Metrics() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		certs, err := s.kube.List(r.Context())
		up := 1
		if err != nil {
			up = 0
		}
		fmt.Fprintf(w, "# HELP pki_portal_up Whether the portal can list certificates from Kubernetes.\n# TYPE pki_portal_up gauge\npki_portal_up %d\n", up)

		fmt.Fprint(w, "# HELP pki_portal_certificate_expiry_timestamp_seconds When each portal certificate expires.\n# TYPE pki_portal_certificate_expiry_timestamp_seconds gauge\n")
		for _, c := range certs {
			if c.Leaf != nil {
				fmt.Fprintf(w, "pki_portal_certificate_expiry_timestamp_seconds{cert_id=%q,name=%q,issuer=%q,mode=%q} %d\n",
					label(c.ID), label(firstName(c)), label(c.Issuer), c.Mode, c.Leaf.NotAfter.Unix())
			}
		}
		fmt.Fprint(w, "# HELP pki_portal_certificate_ready 1 if the certificate is issued and healthy.\n# TYPE pki_portal_certificate_ready gauge\n")
		for _, c := range certs {
			ready := 0
			if c.State == kube.Ready {
				ready = 1
			}
			fmt.Fprintf(w, "pki_portal_certificate_ready{cert_id=%q,name=%q,issuer=%q,mode=%q,state=%q} %d\n",
				label(c.ID), label(firstName(c)), label(c.Issuer), c.Mode, c.State, ready)
		}

		s.counters.mu.Lock()
		keys := make([][2]string, 0, len(s.counters.issued))
		for k := range s.counters.issued {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i][0]+keys[i][1] < keys[j][0]+keys[j][1] })
		fmt.Fprint(w, "# HELP pki_portal_issued_total Certificates issued through the portal since start.\n# TYPE pki_portal_issued_total counter\n")
		for _, k := range keys {
			fmt.Fprintf(w, "pki_portal_issued_total{issuer=%q,mode=%q} %d\n", k[0], k[1], s.counters.issued[k])
		}
		s.counters.mu.Unlock()

		fmt.Fprint(w, "# HELP pki_portal_hook_deliveries_total Hook deliveries since start.\n# TYPE pki_portal_hook_deliveries_total counter\n")
		for k, v := range s.hooks.Counts() {
			fmt.Fprintf(w, "pki_portal_hook_deliveries_total{type=%q,result=%q} %d\n", k[0], k[1], v)
		}
		fmt.Fprint(w, "# HELP pki_portal_hook_failing 1 if the hook's last delivery failed.\n# TYPE pki_portal_hook_failing gauge\n")
		if hs, err := s.store.AllHooks(); err == nil {
			for _, h := range hs {
				failing := 0
				if !h.LastRun.IsZero() && !h.LastOK {
					failing = 1
				}
				fmt.Fprintf(w, "pki_portal_hook_failing{hook_id=\"%d\",cert_id=%q,type=%q} %d\n", h.ID, label(h.CertID), h.Type, failing)
			}
		}
	})
}
