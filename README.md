# ingress-snippet-blocker

KubeWarden policy that blocks dangerous `ingress-nginx` annotations associated with CVE-2025-1974.

## Blocked Annotations

- `nginx.ingress.kubernetes.io/auth-url`
- `nginx.ingress.kubernetes.io/auth-tls-match-cn`
- `nginx.ingress.kubernetes.io/mirror`
- `nginx.ingress.kubernetes.io/permanent-redirect`
- `nginx.ingress.kubernetes.io/configuration-snippet`
- `nginx.ingress.kubernetes.io/server-snippet`

## Usage

```sh
make build test
kwctl push --destination registry.example.com/ingress-snippet-blocker:v0.2.0 --policy-path target/wasm32-unknown-unknown/release/policy.wasm
```
