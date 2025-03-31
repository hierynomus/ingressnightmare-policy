# ingressnightmare-blocker

KubeWarden policy that blocks dangerous `ingress-nginx` annotations associated with CVE-2025-1974.

## Blocked Annotations

- `nginx.ingress.kubernetes.io/auth-url`
- `nginx.ingress.kubernetes.io/auth-tls-match-cn`
- `nginx.ingress.kubernetes.io/mirror-host`
- `nginx.ingress.kubernetes.io/mirror-target`
- `nginx.ingress.kubernetes.io/configuration-snippet` (Optional)
- `nginx.ingress.kubernetes.io/server-snippet` (Optional)
- `nginx.ingress.kubernetes.io/auth-snippet` (Optional)
