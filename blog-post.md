# Ending the IngressNightmare: How SUSE Secures Your Kubernetes Clusters from External and Internal Threats

**March 2025**

In March 2025, Wiz researchers disclosed a set of critical vulnerabilities in the popular `ingress-nginx` controller for Kubernetes. Collectively referred to as **IngressNightmare**, these issues (CVE-2025-1097, CVE-2025-1098, CVE-2025-24513, CVE-2025-24514, and CVE-2025-1974) allow unauthenticated attackers to exploit the Ingress admission controller, potentially achieving remote code execution or escalating privileges in the cluster.

In this post, we’ll walk through how SUSE’s security stack—including **NeuVector**, **KubeWarden**, and the **Application Collection**—can be layered to mitigate both external and internal risks related to this vulnerability.

But first let's recap the IngressNightmare attack chain.

- **CVE-2025-1097 (8.8 High)**: Configuration injection via unsanitized auth-tls-match-cn annotation. The `auth-tls-match-cn` Ingress annotation can be used to inject configuration into nginx. This can lead to arbitrary code execution in the context of the ingress-nginx controller, and disclosure of Secrets accessible to the controller.
- **CVE-2025-1098 (8.8 High)**: Configuration injection via unsanitized mirror annotations. The `mirror-target` and `mirror-host` Ingress annotations can be used to inject arbitrary configuration into nginx. This can lead to arbitrary code execution in the context of the ingress-nginx controller, and disclosure of Secrets accessible to the controller.
- **CVE-2025-24514 (8.8 High)**: Configuration injection via unsanitized auth-url annotation. In ingress-nginx, the `auth-url` Ingress annotation can be used to inject configuration into nginx. This can lead to arbitrary code execution in the context of the ingress-nginx controller, and disclosure of Secrets accessible to the controller.
- **CVE-2025-24513 (4.8 Medium)**: Auth secret file path traversal vulnerability. Attacker-provided data is included in a filename by the ingress-nginx Admission Controller feature, resulting in directory traversal within the container. This could result in denial of service, or when combined with other vulnerabilities, limited disclosure of Secret objects from the cluster.
- **CVE-2025-1974 (9.8 Critical)**: RCE escalation. An unauthenticated attacker with access to the pod network can achieve arbitrary code execution in the context of the ingress-nginx controller. This can lead to disclosure of Secrets accessible to the controller. (In the default installation, the controller can access all Secrets cluster-wide.)

Of these 5 vulnerabilities, the 3 configuration injection issues (CVE-2025-1097, CVE-2025-1098, and CVE-2025-24514) can be used as a trampoline to exploit the RCE vulnerability (CVE-2025-1974). This is because the `auth-tls-match-cn`, `mirror-target`, `mirror-host`, and `auth-url` annotations can be used to inject arbitrary configuration into the NGINX controller, which can then be leveraged to execute arbitrary code.

## Network-Level Defense with SUSE Security

IngressNightmare takes advantage of the fact that the `ingress-nginx` validating admission webhook can sometimes be exposed—intentionally or accidentally—outside the cluster. Once accessible, it can be invoked directly without authentication, bypassing Kubernetes RBAC.

With **SUSE Security**, security teams can apply **network policies** to ensure that only the Kubernetes API server can access the `ingress-nginx-admission` service. This effectively blocks external actors—and even internal pods—from reaching the vulnerable webhook endpoint.

Using SUSE Security's deep packet inspection and container-aware firewalls, you can:

- Block all external access to the admission controller
- Enforce that only the API server has access to webhook ports
- Monitor and alert on any lateral movement attempts

This protects against unauthenticated attacks originating from outside the cluster.

To demonstrate how SUSE Security can be used to secure the admission controller, we need to create a NeuVector security rule that restricts access to the `ingress-nginx-controller-admission` service. This rule should ensure that only the Kubernetes API server can access the webhook, effectively blocking any unauthorized access. Let's investigate how the admission controller is exposed.

The `ingress-nginx` Admission Controller is exposed through a Kubernetes Service of type `ClusterIP`, which means it is only accessible from within the cluster. However, if the service is misconfigured or exposed through a `LoadBalancer` or `NodePort`, it could be accessed from outside the cluster. The Service exposes the webhook on port 443, which is linked to port 8443 on the `ingress-nginx-controller` pod. So to secure the admission controller, we need to ensure that only the Kubernetes API server can access the `ingress-nginx-controller-admission` service on port 443.

Here is an excerpt from the SUSE Security Security Rule that restricts access to the `ingress-nginx-controller-admission` service, allowing only traffic from the Kubernetes API server:

```yaml
ingress:
  - action: deny
  applications:
  - any
  name: ingress-nginx-ingress-2
  ports: tcp/8443
  priority: 0
  selector:
    comment: ""
    criteria:
    - key: namespace
      op: '!='
      value: kube-system
    name: not-kube-system
target:
  policymode: N/A
  selector:
    comment: The Ingress-Nginx service
    criteria:
    - key: service
      op: =
      value: ingress-nginx*
    name: ingress-nginx
```

This would block any access on port 8443 to the `ingress-nginx-controller-admission` service from any namespace other than `kube-system`. Ensuring that the Kubernetes API server is the only entity that can communicate with the `ingress-nginx` admission webhook. Any other pod or external entity will be denied at the network layer. This policy will effectively ensure that CVE-2025-1974 cannot be exploited from outside or inside the cluster.

The full NeuVector security rule set can be found [here](https://github.com/hierynomus/ingressnightmare-policy/blob/main/nvsecurityrule.yaml)

## Protecting Against Supply Chain Compromise

Even with network-layer protections, there remains a second, subtle attack vector: a **compromised application image, Helm chart or CI/CD pipeline** that introduces a malicious workload with permissions to create Kubernetes `Ingress` resources. The attacker can then leverage the vulnerable webhook to inject malicious configuration, exploiting the configuration injection vulnerabilities (CVE-2025-1097, CVE-2025-1098, and CVE-2025-24514) of IngressNightmare.

In this scenario, the attacker doesn’t bypass the API—they use it legitimately. The malicious Ingress is accepted by the API server and forwarded to the vulnerable webhook, which may lead to configuration injection which can lead to exposing sensitive data such as secrets or certificates available to the ingress controller.

Fear not however, as SUSE’s security stack provides a solution to this threat vector as well.

## Early Detection and Policy Enforcement with KubeWarden

To protect your cluster against this, we can use **KubeWarden** to enforce policy-as-code admission rules. These policies validate incoming Kubernetes objects—even before the vulnerable webhook is invoked.

Here is an example `ClusterAdmissionPolicy` that blocks Ingress definitions containing dangerous annotations:

```yaml
apiVersion: policies.kubewarden.io/v1
kind: ClusterAdmissionPolicy
metadata:
  name: ingressnightmare-blocker
spec:
  module: ghcr.io/hierynomus/kw-policies/ingressnightmare-policy:v0.1.0
  rules:
    - apiGroups: ["networking.k8s.io"]
      apiVersions: ["v1"]
      resources: ["ingresses"]
      operations: ["CREATE", "UPDATE"]
  settings:
    allow_config_snippets: false
  mode: protect
```

This policy is powered by a Rust-based WebAssembly (WASM) module that inspects Ingress annotations and rejects any Ingress containing the vulnerable annotations:

- `nginx.ingress.kubernetes.io/auth-url`
- `nginx.ingress.kubernetes.io/auth-tls-match-cn`
- `nginx.ingress.kubernetes.io/mirror-target`
- `nginx.ingress.kubernetes.io/mirror-host`

Next to that, if configured, it can also block the following annotations that are known for injecting random NGINX configuration:
- `nginx.ingress.kubernetes.io/configuration-snippet`
- `nginx.ingress.kubernetes.io/server-snippet`
- `nginx.ingress.kubernetes.io/auth-snippet`

By positioning KubeWarden’s admission webhook to run before others (lexicographically), platform teams can block dangerous Ingress objects before they ever reach the vulnerable ingress-nginx admission webhook.

To do this, ensure KubeWarden's `ValidatingWebhookConfiguration` is named to sort alphabetically before other admission webhooks. For example `00-kubewarden-ingress-blocker`.

Additionally, configure the webhook with a `failurePolicy: Fail` to guarantee that any issues with policy evaluation result in a denial of the request. Below is a complete example of a `ValidatingWebhookConfiguration` resource tailored to enforce the KubeWarden ingress policy early:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: 00-kubewarden-ingress-blocker
webhooks:
  - name: ingress.kubewarden.io
    clientConfig:
      service:
        name: kubewarden-policy-server
        namespace: kubewarden
        path: "/validate"
        port: 443
      caBundle: <Base64-encoded-CA-bundle>
    rules:
      - apiGroups: ["networking.k8s.io"]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["ingresses"]
        scope: "Namespaced"
    admissionReviewVersions: ["v1"]
    sideEffects: None
    failurePolicy: Fail
    matchPolicy: Exact
    timeoutSeconds: 10
```

Replace `<Base64-encoded-CA-bundle>` with the appropriate CA bundle for your policy server’s TLS certificate.

This configuration ensures KubeWarden receives and evaluates Ingress resources before any other admission webhook, and any policy failure results in a rejection of the ingress resource. This effectively blocks the exploitation of CVE-2025-1097, CVE-2025-1098, and CVE-2025-24514.

So far, we have secured the network layer with NeuVector and the API layer with KubeWarden. But SUSE also offers a way to secure the software supply chain.

## Securing the Software Supply Chain with SUSE Application Collection

Security doesn’t start at runtime, it starts at the source.

To further reduce the risk of supply chain-based attacks, SUSE provides the [**Application Collection**](https://apps.rancher.io): a curated repository of trusted, SLSA-attested application packages. Every application in the collection includes:

- **SLSA Level 3 provenance and verification**
- **Cryptographic signatures**
- **Continuous Vulnerability scanning**
- **Regularly patched Helm charts and images**

When combined with NeuVector and KubeWarden, the Application Collection ensures that what you deploy is what you expect, no tampering, no surprises.

## Conclusion

IngressNightmare is a wake-up call for defense-in-depth. With SUSE's Open Source Kubernetes security stack, teams can:

- Prevent unauthorized network access with **SUSE Security**
- Block unsafe resources at the API level with **KubeWarden**
- Deploy only trusted workloads from a verified supply chain using the **Application Collection**

By combining these tools, platform engineers and security teams gain visibility, control, and peace of mind.

To learn more, visit [KubeWarden](https://kubewarden.io) and [SUSE Security](https://www.suse.com/products/rancher/security/).

_Stay secure. Stay ahead._
