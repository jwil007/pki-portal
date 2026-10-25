package hooks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// semaphore starts a Semaphore (Ansible) task template, passing the
// certificate details as extra vars, so a playbook can install it.
type semaphore struct{}

func init() { Register(semaphore{}) }

func (semaphore) Type() string   { return "semaphore" }
func (semaphore) Label() string  { return "Semaphore task" }
func (semaphore) NeedsKey() bool { return false }
func (semaphore) Help() string {
	return "Runs a Semaphore task template with extra vars pki_cert_id, pki_cert_names, pki_cert_serial and pki_portal_url. The playbook fetches the cert itself, e.g. with a pull-API token."
}

func (semaphore) Fields() []Field {
	return []Field{
		{Name: "project_id", Label: "Project ID", Kind: "number", Required: true, Help: "From the Semaphore URL: /project/<id>/…"},
		{Name: "template_id", Label: "Task template ID", Kind: "number", Required: true, Help: "From the template's URL: …/templates/<id>"},
	}
}

func (s semaphore) Prepare(_ context.Context, env *Env, cfg map[string]string) (map[string]string, error) {
	if env.SemaphoreURL == "" || env.SemaphoreToken == "" {
		return nil, fmt.Errorf("Semaphore isn't configured on the portal (PORTAL_SEMAPHORE_URL and PORTAL_SEMAPHORE_TOKEN)")
	}
	if err := required(cfg, s.Fields()); err != nil {
		return nil, err
	}
	for _, k := range []string{"project_id", "template_id"} {
		if _, err := strconv.Atoi(cfg[k]); err != nil {
			return nil, fmt.Errorf("%s must be a number", k)
		}
	}
	return nil, nil
}

func (semaphore) Deliver(ctx context.Context, env *Env, cfg map[string]string, ev Event, _ Material) error {
	tid, _ := strconv.Atoi(cfg["template_id"])
	vars, _ := json.Marshal(map[string]any{
		"pki_cert_id":     ev.CertID,
		"pki_cert_names":  ev.Names,
		"pki_cert_serial": ev.Serial,
		"pki_event":       ev.Event,
		"pki_portal_url":  ev.URL,
	})
	// Semaphore takes extra vars as a JSON string in "environment".
	body, _ := json.Marshal(map[string]any{"template_id": tid, "environment": string(vars)})
	url := strings.TrimSuffix(env.SemaphoreURL, "/") + "/api/project/" + cfg["project_id"] + "/tasks"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+env.SemaphoreToken)
	resp, err := env.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("Semaphore returned %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}
