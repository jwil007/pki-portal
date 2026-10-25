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
| `PORTAL_PASSWORD` | (required) | login password |
| `PORTAL_LISTEN` | `:8080` | |
| `PORTAL_DATA_DIR` | `./data` (`/data` in the image) | SQLite audit log + session key |
| `PORTAL_NAMESPACE` | `pki-managed` | where certificates are created |
| `PORTAL_PUBLIC_ISSUER` | `letsencrypt-staging` | set `letsencrypt-prod` once you're happy |
| `PORTAL_STEPCA_URL` | `https://step-certificates.pki.svc.cluster.local` | |
| `PORTAL_STEPCA_PROVISIONER` | `pki-portal` | JWK provisioner name |
| `PORTAL_STEPCA_PASSWORD` | (empty: internal certs disabled) | provisioner key password |
| `PORTAL_STEPCA_DIAL` | | `host:port` to connect to instead, e.g. the LB `10.0.50.205:443` from a laptop |
| `PORTAL_INTERNAL_LIFETIME` | provisioner default (1 year) | |
| `PORTAL_IP_RANGES` | RFC 1918 ranges | allowed IP SANs |
| `PORTAL_DOMAINS` | `wilsonfi.dev,wilsonfi.com` | |
| `PORTAL_PUBLIC_DOMAINS` | `wilsonfi.dev` | |
| `PORTAL_CA_CONFIGMAP` | `pki/step-certificates-certs` | step-ca root + intermediate (CA page, TLS trust) |
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
