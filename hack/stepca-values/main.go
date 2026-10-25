// Command stepca-values edits the step-ca Helm values stored in a Kubernetes
// Secret (data."values.yaml", as used by the step-certificates chart with
// valuesFrom). It reads the decrypted Secret on stdin and writes the edited
// Secret to stdout, so it slots between `sops -d` and `sops encrypt`.
//
// It parses and writes YAML with sigs.k8s.io/yaml, the library Helm uses, so
// what it shows is exactly what step-ca will get (no YAML 1.1 surprises such
// as a bare `y:` key becoming `true`).
//
//	sops -d values.sops.yaml | go run ./hack/stepca-values -diff -add-provisioner p.json -set-crl crl.json
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"strings"

	"sigs.k8s.io/yaml"
)

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	var provs multi
	flag.Var(&provs, "add-provisioner", "JSON file with a provisioner to append (skipped if the name exists); repeatable")
	crlFile := flag.String("set-crl", "", "JSON file with the top-level \"crl\" block for ca.json")
	diff := flag.Bool("diff", false, "print a redacted before/after of ca.json instead of the Secret")
	flag.Parse()
	if err := run(os.Stdin, os.Stdout, provs, *crlFile, *diff); err != nil {
		fmt.Fprintln(os.Stderr, "stepca-values:", err)
		os.Exit(1)
	}
}

func run(in io.Reader, out io.Writer, provFiles []string, crlFile string, diff bool) error {
	raw, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	var secret map[string]any
	if err := yaml.Unmarshal(raw, &secret); err != nil {
		return fmt.Errorf("parsing Secret: %w", err)
	}
	data, _ := secret["data"].(map[string]any)
	enc, _ := data["values.yaml"].(string)
	if enc == "" {
		return errors.New(`Secret has no data."values.yaml"`)
	}
	valuesYAML, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return err
	}
	var values map[string]any
	if err := yaml.Unmarshal(valuesYAML, &values); err != nil {
		return fmt.Errorf("parsing values.yaml: %w", err)
	}
	caJSON, err := dig(values, "inject", "config", "files", "ca.json")
	if err != nil {
		return err
	}
	before := deepCopy(caJSON)

	authority, ok := caJSON["authority"].(map[string]any)
	if !ok {
		return errors.New("ca.json has no authority block")
	}
	list, _ := authority["provisioners"].([]any)
	for _, f := range provFiles {
		var p map[string]any
		if err := readJSON(f, &p); err != nil {
			return err
		}
		if exists(list, p["name"]) {
			fmt.Fprintf(os.Stderr, "provisioner %v already present, skipping\n", p["name"])
			continue
		}
		list = append(list, p)
	}
	authority["provisioners"] = list
	if crlFile != "" {
		var crl map[string]any
		if err := readJSON(crlFile, &crl); err != nil {
			return err
		}
		caJSON["crl"] = crl
	}

	newValues, err := yaml.Marshal(values)
	if err != nil {
		return err
	}
	// Round-trip check: re-parse what we'll write and make sure it's identical.
	var check map[string]any
	if err := yaml.Unmarshal(newValues, &check); err != nil {
		return fmt.Errorf("re-parsing output: %w", err)
	}
	if !reflect.DeepEqual(normalize(check), normalize(values)) {
		return errors.New("output doesn't round-trip; refusing to write it")
	}
	if err := checkJWKs(check); err != nil {
		return err
	}

	if diff {
		return printDiff(out, before, caJSON)
	}
	data["values.yaml"] = base64.StdEncoding.EncodeToString(newValues)
	o, err := yaml.Marshal(secret)
	if err != nil {
		return err
	}
	_, err = out.Write(o)
	return err
}

func dig(m map[string]any, path ...string) (map[string]any, error) {
	cur := m
	for _, p := range path {
		next, ok := cur[p].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("values have no %s", strings.Join(path, "."))
		}
		cur = next
	}
	return cur, nil
}

func exists(list []any, name any) bool {
	for _, p := range list {
		if m, ok := p.(map[string]any); ok && m["name"] == name {
			return true
		}
	}
	return false
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// normalize converts through JSON so number types compare equal.
func normalize(v any) any {
	b, _ := json.Marshal(v)
	var out any
	json.Unmarshal(b, &out)
	return out
}

func deepCopy(m map[string]any) map[string]any {
	var out map[string]any
	b, _ := json.Marshal(m)
	json.Unmarshal(b, &out)
	return out
}

// checkJWKs makes sure every EC provisioner key still has string x and y.
func checkJWKs(values map[string]any) error {
	caJSON, err := dig(values, "inject", "config", "files", "ca.json")
	if err != nil {
		return err
	}
	auth, _ := caJSON["authority"].(map[string]any)
	list, _ := auth["provisioners"].([]any)
	for _, p := range list {
		m, _ := p.(map[string]any)
		key, ok := m["key"].(map[string]any)
		if !ok || key["kty"] != "EC" {
			continue
		}
		for _, k := range []string{"x", "y", "crv"} {
			if _, ok := key[k].(string); !ok {
				return fmt.Errorf("provisioner %v: key field %q missing or not a string", m["name"], k)
			}
		}
	}
	return nil
}

var redact = regexp.MustCompile(`("encryptedKey": )"[^"]+"|-----BEGIN [A-Z ]+-----[^"]*-----END [A-Z ]+-----`)

func printDiff(out io.Writer, before, after map[string]any) error {
	b, _ := json.MarshalIndent(before, "", "  ")
	a, _ := json.MarshalIndent(after, "", "  ")
	clean := func(s []byte) []string {
		return strings.Split(redact.ReplaceAllString(string(s), `$1"<redacted>"`), "\n")
	}
	bl, al := clean(b), clean(a)
	// Simple line diff: lines only in one side, in order (fine for appends).
	inB := map[string]int{}
	for _, l := range bl {
		inB[l]++
	}
	var buf bytes.Buffer
	for _, l := range al {
		if inB[l] > 0 {
			inB[l]--
			continue
		}
		fmt.Fprintln(&buf, "+ "+l)
	}
	inA := map[string]int{}
	for _, l := range al {
		inA[l]++
	}
	for _, l := range bl {
		if inA[l] > 0 {
			inA[l]--
			continue
		}
		fmt.Fprintln(&buf, "- "+l)
	}
	if buf.Len() == 0 {
		fmt.Fprintln(out, "no changes")
		return nil
	}
	_, err := out.Write(buf.Bytes())
	return err
}
