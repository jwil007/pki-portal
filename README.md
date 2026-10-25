# PKI Portal

A small self-service web UI for issuing certificates in a homelab.

- **Public** certs come from Let's Encrypt through cert-manager (DNS-01 via
  Cloudflare). The portal never holds Cloudflare or ACME account credentials.
- **Internal** certs are signed directly by step-ca through a JWK provisioner
  owned by the portal. There's no ACME and no DNS records, so they work for names
  that aren't in public DNS and for IP addresses, and they issue instantly.

Lab tool: one password, no user accounts, meant for an internal network only.

```
 browser ──► pki-portal ──(Kubernetes API)──► cert-manager ──► Let's Encrypt   (public)
                │  │                                │
                │  └──(JWK token, /1.0/sign)───────────────────► step-ca       (internal)
                │                                   ▼
                │                        namespace pki-managed:
                │                        Certificates, CertificateRequests,
                └── SQLite (audit log)   Secrets (tls.crt / tls.key / ca.crt)
```

## What each option does

| Choice in the UI | Public (Let's Encrypt) | Internal (step-ca) | Where the key lives | Renewal |
| --- | --- | --- | --- | --- |
| Managed | `Certificate` | Secret `<id>` (tls.crt, tls.key, ca.crt) | Secret in `pki-managed` | cert-manager / portal scheduler at 2/3 of lifetime |
| Unmanaged | `CertificateRequest` | Secret `<id>` without tls.key | Portal memory only, for `PORTAL_KEY_TTL` (30m) | none, issue a new one |
| Upload CSR | `CertificateRequest` | Secret `<id>` without tls.key | Your device; the portal never sees it | upload a new CSR |

Everything the portal creates is labelled `app.kubernetes.io/managed-by=pki-portal`
and `pki.wilsonfi.dev/cert-id=<id>`; step-ca ones also carry
`pki.wilsonfi.dev/backend=step-ca`.

Downloads are rendered on the fly: PEM cert / full chain / CA chain, DER `.cer`,
PKCS#12 legacy (3DES/SHA-1, for ClearPass and appliances) or modern (AES-256),
`.pfx`, combined key+chain PEM, the key as PKCS#8, traditional (`BEGIN RSA
PRIVATE KEY`) or encrypted PKCS#8, and a ZIP of PEM files.

Name policy: DNS names under `PORTAL_DOMAINS`; public certs only under
`PORTAL_PUBLIC_DOMAINS`; IP SANs only on internal certs, within
`PORTAL_IP_RANGES`. step-ca enforces the same rules in the provisioner policy.
CSRs must have a valid signature and an RSA ≥ 2048 or ECDSA P-256/P-384 key.

## Configuration

All settings are environment variables.

| Variable | Default | |
| --- | --- | --- |
| `PORTAL_PASSWORD` | (required, or `_FILE`) | login password. With `PORTAL_PASSWORD_FILE` it's re-read on every login, so rotating the Secret needs no restart |
| `PORTAL_LISTEN` | `:8080` | |
| `PORTAL_DATA_DIR` | `./data` (`/data` in the image) | SQLite audit log + session key |
| `PORTAL_NAMESPACE` | `pki-managed` | where certificates are created |
| `PORTAL_PUBLIC_ISSUER` | `letsencrypt-staging` | set `letsencrypt-prod` once you're happy |
| `PORTAL_STEPCA_URL` | `https://step-certificates.pki.svc.cluster.local` | |
| `PORTAL_STEPCA_PROVISIONER` | `pki-portal` | JWK provisioner name |
| `PORTAL_STEPCA_PASSWORD` | (empty: internal certs disabled) | provisioner key password |
| `PORTAL_STEPCA_DIAL` | | `host:port` to connect to instead, e.g. the LB `10.0.50.205:443` from a laptop |
| `PORTAL_INTERNAL_LIFETIME` | provisioner default (1 year) | |
| `PORTAL_STEPCA_CLIENT_PROVISIONER` | (empty: client certs disabled) | JWK provisioner for EAP-TLS user/device certs, same password |
| `PORTAL_CLIENT_EMAIL_DOMAIN` | `ad.wilsonfi.dev` | default email/UPN domain for user certs |
| `PORTAL_GITOPS_NAMESPACE` | (empty: disabled) | show this namespace's cert-manager Certificates read-only |
| `PORTAL_IP_RANGES` | RFC 1918 ranges | allowed IP SANs |
| `PORTAL_DOMAINS` | `wilsonfi.dev,wilsonfi.com` | |
| `PORTAL_PUBLIC_DOMAINS` | `wilsonfi.dev` | |
| `PORTAL_CA_CONFIGMAP` | `pki/step-certificates-certs` | step-ca root + intermediate (CA page, TLS trust) |
| `PORTAL_KEY_TTL` | `30m` | how long unmanaged keys stay downloadable |
| `PORTAL_INSECURE_COOKIE` | `false` | `true` only for plain-http local runs |
| `PORTAL_BASE_URL` | `http://localhost:8080` | used in notification links and snippets |
| `PORTAL_NTFY_URL` | | default ntfy topic for notify hooks |
| `PORTAL_SEMAPHORE_URL` / `PORTAL_SEMAPHORE_TOKEN` | | enables Semaphore hooks |
| `PORTAL_SSH_KEY_FILE` | generated in the data dir | the portal's SSH identity for SSH push hooks |
| `PORTAL_METRICS_LISTEN` | `:9090` | Prometheus `/metrics`, on its own port so it isn't exposed through the ingress |

Secrets can be given as `NAME_FILE` pointing at a file (how Kubernetes mounts
Secrets): `PORTAL_STEPCA_PASSWORD`, `PORTAL_SEMAPHORE_TOKEN`, `PORTAL_NTFY_URL`.

Kubernetes access: in-cluster service account when running in a pod, otherwise
`$KUBECONFIG` or `~/.kube/config`.

## Run it

From source, against the cluster in your kubeconfig:

```sh
read -rs PORTAL_PASSWORD && export PORTAL_PASSWORD
PORTAL_INSECURE_COOKIE=true go run ./cmd/pki-portal
# http://localhost:8080
```

As a container:

```sh
read -rs PORTAL_PASSWORD && export PORTAL_PASSWORD
docker run --rm -p 8080:8080 -e PORTAL_PASSWORD -e PORTAL_INSECURE_COOKIE=true \
  -v "$HOME/.kube/config:/kubeconfig:ro" -e KUBECONFIG=/kubeconfig \
  -v pki-portal-data:/data ghcr.io/jwil007/pki-portal:latest
```

## step-ca provisioner

The portal fetches its provisioner's encrypted key from step-ca's public
`/provisioners` endpoint and decrypts it with `PORTAL_STEPCA_PASSWORD`, so the
only secret it holds is that password. The provisioner entry in step-ca's
`ca.json`:

```json
{
  "type": "JWK", "name": "pki-portal",
  "key": { "...public JWK..." }, "encryptedKey": "<JWE>",
  "claims": { "defaultTLSCertDuration": "8760h", "maxTLSCertDuration": "8760h" },
  "policy": { "x509": {
    "allow": { "dns": ["wilsonfi.dev", "*.wilsonfi.dev", "wilsonfi.com", "*.wilsonfi.com"],
               "ip":  ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] },
    "allowWildcardNames": true } }
}
```

Create the key with `step crypto jwk create pub.json priv.json --kty EC --crv P-256`
and get the `encryptedKey` from `step crypto jose format < priv.json`.

## Client certificates (EAP-TLS)

**Client certs** issues User certs (CN = AD username, email SAN =
`username@PORTAL_CLIENT_EMAIL_DOMAIN`) or Device certs (CN and DNS SAN = the
hostname) through a second JWK provisioner, `pki-portal-clients`. It's separate
because step-ca's name policy also checks the CN, and a bare username like
`testuser` can't match a DNS rule. The portal enforces the naming rules
for it instead. Both profiles get serverAuth + clientAuth (step-ca's default template).

## Revocation

Certificates signed directly by step-ca can be revoked with a reason. step-ca
revocation is passive: the serial goes on step-ca's CRL (with `crl.enabled` in
`ca.json`) at `https://ca.wilsonfi.dev/1.0/crl`, and relying parties such as
ClearPass must fetch that CRL to notice. step-ca has no OCSP. A revoked cert's
stored key is wiped and it stops renewing. Let's Encrypt certs are handled
with "Delete and stop renewing".

## GitOps view

With `PORTAL_GITOPS_NAMESPACE=pki`, the GitOps page shows that namespace's
Certificates (e.g. ClearPass) read-only: status, expiry, a "renewed since your
last download" flag, the cert-manager-built `keystore.p12`, and the p12
passphrase (audited). The portal needs `get` on those Secrets by name only.

## Delivery hooks

Each certificate can have any number of hooks. The portal checks every minute
(and right after a renewal) whether a certificate's serial differs from the one
each hook last delivered, and runs the hook if so. Comparing serials means a
renewal that happened while the portal was down is still delivered. Failures
retry with backoff (1 minute doubling to 1 hour). Every run is in the audit log.

| Hook | What it does |
| --- | --- |
| Notify (ntfy) | Push notification with a link to the certificate |
| Pull API token | Per-certificate token for `GET /api/v1/certs/{id}/{format}`; the UI shows curl and systemd timer snippets |
| Webhook | `POST` JSON event (no key material), signed `X-PKI-Signature: sha256=<HMAC>` |
| Semaphore task | Starts a task template with extra vars `pki_cert_id`, `pki_cert_names`, `pki_cert_serial`, `pki_event`, `pki_portal_url` |
| SSH push | Writes full chain + key (temp file + rename, key `0600`) and runs a reload command; host key pinned on first connect |

Pull API formats are the same as the download form (`fullchain`, `key`,
`p12-legacy`, …). Password formats take `X-PKI-Password`; `?root=1` adds the
root CA for internal certs. The response has `X-PKI-Serial`.

### Adding a driver (e.g. an appliance REST API)

One file in `internal/hooks/` that implements `Driver` and registers itself:

```go
type fortigate struct{}

func init() { Register(fortigate{}) }

func (fortigate) Type() string    { return "fortigate" }
func (fortigate) Label() string   { return "FortiGate" }
func (fortigate) Help() string    { return "Uploads the cert and key via the FortiOS REST API." }
func (fortigate) NeedsKey() bool  { return true }
func (fortigate) Fields() []Field { return []Field{{Name: "host", Label: "Host", Kind: "text", Required: true}} }
func (fortigate) Prepare(ctx context.Context, env *Env, cfg map[string]string) (map[string]string, error) { … }
func (fortigate) Deliver(ctx context.Context, env *Env, cfg map[string]string, ev Event, m Material) error { … }
```

The UI builds the config form from `Fields()`. `Material.Key` is only fetched
when a driver calls it. No vendor drivers ship yet.

## Metrics

`/metrics` on `PORTAL_METRICS_LISTEN`:

- `pki_portal_certificate_expiry_timestamp_seconds{cert_id,name,issuer,mode}`
- `pki_portal_certificate_ready{…,state}`
- `pki_portal_issued_total{issuer,mode}`
- `pki_portal_hook_deliveries_total{type,result}`
- `pki_portal_hook_failing{hook_id,cert_id,type}`
- `pki_portal_up`

Example alert: `pki_portal_certificate_expiry_timestamp_seconds - time() < 14*86400`.

## Editing step-ca's values safely

`hack/stepca-values` edits the step-certificates Helm values held in a Secret.
Pipe it between `sops -d` and `sops encrypt`. It parses and writes YAML with
`sigs.k8s.io/yaml`, the library Helm uses, so it can't reintroduce YAML 1.1
surprises (a bare `y:` JWK key parsed as `true` once took step-ca down). It
refuses to write output with an EC key missing `x`/`y`.

```sh
sops -d infra/pki/step-ca-values.sops.yaml \
  | go run ./hack/stepca-values -diff -add-provisioner clients.json -set-crl crl.json
```

## Releases

Push a semver tag (`git tag v0.1.0 && git push origin v0.1.0`). The GitHub
Actions workflow runs the tests and pushes `ghcr.io/jwil007/pki-portal:0.1.0`
(amd64 + arm64).

## Tests

```sh
go test ./...
```

Covers name policy, CSR validation, p12 encoding, the key stash, cert-manager
interactions (fake clientsets) and the HTTP flow (login, cross-origin POST
rejection, issuance, duplicate warning, audit).

## Backup and recovery

- **SQLite volume**: only the audit log. Losing it loses history, nothing else.
- **`pki-managed`**: the Certificates and their Secrets. If lost, re-issue; for
  managed certs that just means creating them again.
- The deployment itself is rebuilt from Git (`wilsonfi-k8s`, `apps/prod/pki-portal`).
