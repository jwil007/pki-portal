package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

const values = `inject:
  enabled: true
  config:
    files:
      ca.json:
        dnsNames: [ca.wilsonfi.dev]
        authority:
          enableAdmin: false
          provisioners:
            - type: JWK
              name: admin
              key: {kty: EC, crv: P-256, 'x': abc, 'y': def}
              encryptedKey: secret-jwe
`

func secretYAML() string {
	return "apiVersion: v1\nkind: Secret\nmetadata:\n  name: step-ca-values\ndata:\n  values.yaml: " +
		base64.StdEncoding.EncodeToString([]byte(values)) + "\n"
}

func TestAddProvisionerKeepsYAsString(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "p.json")
	os.WriteFile(p, []byte(`{"type":"JWK","name":"pki-portal-clients","key":{"kty":"EC","crv":"P-256","x":"n","y":"y"},"encryptedKey":"e"}`), 0o600)
	crl := filepath.Join(dir, "crl.json")
	os.WriteFile(crl, []byte(`{"enabled":true,"generateOnRevoke":true}`), 0o600)

	var out bytes.Buffer
	if err := run(strings.NewReader(secretYAML()), &out, []string{p, p}, crl, false); err != nil {
		t.Fatal(err)
	}
	var sec map[string]any
	yaml.Unmarshal(out.Bytes(), &sec)
	dec, _ := base64.StdEncoding.DecodeString(sec["data"].(map[string]any)["values.yaml"].(string))
	var v map[string]any
	if err := yaml.Unmarshal(dec, &v); err != nil {
		t.Fatal(err)
	}
	ca, _ := dig(v, "inject", "config", "files", "ca.json")
	provs := ca["authority"].(map[string]any)["provisioners"].([]any)
	if len(provs) != 2 {
		t.Fatalf("got %d provisioners, want 2 (second add should be skipped)", len(provs))
	}
	for _, p := range provs {
		key := p.(map[string]any)["key"].(map[string]any)
		if _, ok := key["y"].(string); !ok {
			t.Errorf("%v: y is %T, want string", p.(map[string]any)["name"], key["y"])
		}
	}
	if ca["crl"].(map[string]any)["enabled"] != true || ca["authority"].(map[string]any)["enableAdmin"] != false {
		t.Error("crl or booleans wrong")
	}
	if strings.Contains(string(dec), "\ny:") || strings.Contains(string(dec), " y: ") {
		t.Errorf("bare y key in output:\n%s", dec)
	}
}

func TestDiffRedacts(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "p.json")
	os.WriteFile(p, []byte(`{"type":"JWK","name":"c","encryptedKey":"topsecret"}`), 0o600)
	var out bytes.Buffer
	if err := run(strings.NewReader(secretYAML()), &out, []string{p}, "", true); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "topsecret") || strings.Contains(out.String(), "secret-jwe") || !strings.Contains(out.String(), `"name": "c"`) {
		t.Errorf("diff:\n%s", out.String())
	}
}

func TestDetectsBrokenKey(t *testing.T) {
	broken := strings.Replace(values, "'y': def", "y: def", 1) // the bug that crashed step-ca
	sec := "data:\n  values.yaml: " + base64.StdEncoding.EncodeToString([]byte(broken)) + "\n"
	if err := run(strings.NewReader(sec), &bytes.Buffer{}, nil, "", false); err == nil {
		t.Error("bare y key not detected")
	}
}
