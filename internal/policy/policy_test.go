package policy

import "testing"

func TestCheckACME(t *testing.T) {
	p := Policy{Domains: []string{"wilsonfi.dev", "wilsonfi.com"}, PublicDomains: []string{"wilsonfi.dev"}}
	cases := []struct {
		names  []string
		public bool
		ok     bool
	}{
		{[]string{"fw.wilsonfi.dev"}, true, true},
		{[]string{"wilsonfi.dev"}, true, true},
		{[]string{"*.lab.wilsonfi.dev"}, true, true},
		{[]string{"host.wilsonfi.com"}, false, true},
		{[]string{"host.wilsonfi.com"}, true, false},
		{[]string{"evilwilsonfi.dev"}, false, false},
		{[]string{"example.com"}, false, false},
		{[]string{"10.0.0.1"}, false, false},
		{[]string{"a.*.wilsonfi.dev"}, false, false},
		{[]string{"-bad.wilsonfi.dev"}, false, false},
		{[]string{"under_score.wilsonfi.dev"}, false, false},
		{[]string{"localhost"}, false, false},
		{nil, false, false},
	}
	for _, c := range cases {
		err := p.CheckACME(c.names, c.public)
		if (err == nil) != c.ok {
			t.Errorf("CheckACME(%v, public=%v) err=%v, want ok=%v", c.names, c.public, err, c.ok)
		}
	}
}

func TestSplitNames(t *testing.T) {
	got := SplitNames(" FW.wilsonfi.dev, fw.wilsonfi.dev.\nvpn.wilsonfi.dev ")
	if len(got) != 2 || got[0] != "fw.wilsonfi.dev" || got[1] != "vpn.wilsonfi.dev" {
		t.Fatalf("got %v", got)
	}
}
