# Security Policy

## Supported Versions

Security updates are provided for the default branch and the latest stable
release only.

| Version | Supported |
| --- | --- |
| Default branch | :white_check_mark: |
| Latest stable release | :white_check_mark: |
| Older releases | :x: |

## Reporting a Vulnerability

Do not open a public issue for a suspected vulnerability.

Report vulnerabilities privately to Red Hat Product Security:

- Email: [secalert@redhat.com](mailto:secalert@redhat.com)
- Secure contact and OpenPGP key: [Red Hat Security Contacts and Procedures](https://access.redhat.com/security/team/contact)

Include the affected Parsec version, deployment environment, reproduction
steps, exploitation scenario, and potential impact when known. See Red Hat's
[Coordinated Vulnerability Disclosure policy](https://access.redhat.com/articles/red-hat-coordinated-vulnerability-disclosure)
for the complete reporting guidance.

## Response and Coordinated Disclosure

Red Hat Product Security handles acknowledgment, triage, CVE assignment,
response timing, confidentiality, and coordinated disclosure according to its
[Coordinated Vulnerability Disclosure policy](https://access.redhat.com/articles/red-hat-coordinated-vulnerability-disclosure).
Parsec does not make a separate response-time or disclosure-schedule promise.

## Deployment Security

Parsec expects production TLS to terminate at the service mesh, sidecar, or
ingress. See the [deployment security model](README.md#security--deployment-model)
and [architecture documentation](ARCHITECTURE.md#tls-and-network-security).
