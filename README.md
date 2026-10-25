# PKI Portal

A small self-service web UI for issuing certificates in a homelab. It doesn't
issue anything itself: every certificate is a cert-manager object, so renewal,
DNS-01 and the Cloudflare credentials stay with cert-manager. The portal never
holds Cloudflare or ACME account credentials.

Lab tool: one password, no user accounts, meant for an internal network only.

```
 browser ──► pki-portal ──(Kubernetes API)──► cert-manager ──► Let's Encrypt (public)
                │                                   │      └──► step-ca ACME (internal)
                │                                   ▼
                │                        namespace pki-managed:
                │                        Certificates, CertificateRequests,
                └── SQLite (audit log)   Secrets (tls.crt / tls.key)
```

## What each option does

| Choice in the UI | Kubernetes object | Where the key lives | Renewal |
| --- | --- | --- | --- |
| Managed | `Certificate` | Secret `<id>-tls` in `pki-managed` | cert-manager, automatic |
| Unmanaged | `CertificateRequest` with a portal-generated CSR | Portal memory only, for `PORTAL_KEY_TTL` (30m) | none, issue a new one |
| Upload CSR | `CertificateRequest` with your CSR | Your device; the portal never sees it | upload a new CSR |

Everything the portal creates is labelled `app.kubernetes.io/managed-by=pki-portal`
and `pki.wilsonfi.dev/cert-id=<id>`. p12 files are built on the fly at download
time (Legacy 3DES/SHA-1 by default for appliances and ClearPass, or Modern AES-256).

Name policy: DNS names under `PORTAL_DOMAINS`; public certs only under
`PORTAL_PUBLIC_DOMAINS`; no IP SANs (ACME can't validate them). CSRs must have a
valid signature and an RSA ≥ 2048 or ECDSA P-256/P-384 key.

## Configuration

All settings are environment variables.

| Variable | Default | |
| --- | --- | --- |
| `PORTAL_PASSWORD` | (required) | login password |
| `PORTAL_LISTEN` | `:8080` | |
| `PORTAL_DATA_DIR` | `./data` (`/data` in the image) | SQLite audit log + session key |
| `PORTAL_NAMESPACE` | `pki-managed` | where certificates are created |
| `PORTAL_PUBLIC_ISSUER` | `letsencrypt-staging` | set `letsencrypt-prod` once you're happy |
| `PORTAL_INTERNAL_ISSUER` | `step-ca-acme` | |
| `PORTAL_DOMAINS` | `wilsonfi.dev,wilsonfi.com` | |
| `PORTAL_PUBLIC_DOMAINS` | `wilsonfi.dev` | |
| `PORTAL_CA_CONFIGMAP` | `pki/step-certificates-certs` | step-ca root + intermediate for the CA page |
| `PORTAL_KEY_TTL` | `30m` | how long unmanaged keys stay downloadable |
| `PORTAL_INSECURE_COOKIE` | `false` | `true` only for plain-http local runs |

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
