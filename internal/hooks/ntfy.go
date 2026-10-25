package hooks

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ntfy posts a push notification (https://ntfy.sh or a self-hosted server).
type ntfy struct{}

func init() { Register(ntfy{}) }

func (ntfy) Type() string   { return "ntfy" }
func (ntfy) Label() string  { return "Notify (ntfy)" }
func (ntfy) NeedsKey() bool { return false }
func (ntfy) Help() string {
	return "Push notification to your phone via ntfy when the certificate is issued or renewed, with a link to download it. Install the ntfy app and subscribe to the same topic."
}

func (ntfy) Fields() []Field {
	return []Field{
		{Name: "url", Label: "Topic URL", Kind: "text", Placeholder: "https://ntfy.sh/your-unguessable-topic",
			Help: "Leave empty to use the portal's default topic, if one is configured. On ntfy.sh, anyone who knows the topic name can read it, so make it hard to guess."},
		{Name: "token", Label: "Access token", Kind: "password", Help: "Only for protected topics on a self-hosted server."},
	}
}

func (n ntfy) Prepare(_ context.Context, env *Env, cfg map[string]string) (map[string]string, error) {
	if cfg["url"] == "" && env.DefaultNtfyURL == "" {
		return nil, fmt.Errorf("Topic URL is required (no default topic is configured)")
	}
	if u := cfg["url"]; u != "" && !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
		return nil, fmt.Errorf("Topic URL must start with https://")
	}
	return nil, nil
}

func (ntfy) Deliver(ctx context.Context, env *Env, cfg map[string]string, ev Event, _ Material) error {
	url := cfg["url"]
	if url == "" {
		url = env.DefaultNtfyURL
	}
	title := map[string]string{"issued": "Certificate issued", "renewed": "Certificate renewed", "test": "Test notification"}[ev.Event]
	body := fmt.Sprintf("%s\nExpires %s\nSerial %s", strings.Join(ev.Names, ", "), ev.NotAfter.Format("2006-01-02"), ev.Serial)
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Title", title+": "+ev.Names[0])
	req.Header.Set("Tags", "lock")
	req.Header.Set("Click", ev.URL)
	req.Header.Set("Actions", "view, Download, "+ev.URL)
	if t := cfg["token"]; t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}
	resp, err := env.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("ntfy returned %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}
