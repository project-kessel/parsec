# Security Policy

## Supported Versions

This project follows semantic versioning. Security updates are provided for:

| Version | Supported          |
| ------- | ------------------ |
| Latest release on `main` | :white_check_mark: |

## Reporting a Vulnerability

**Do not open public issues for security vulnerabilities.**

To report a security vulnerability in Parsec, please contact the Red Hat Product Security team:

- **Email**: secalert@redhat.com
- **PGP Key**: https://access.redhat.com/security/team/contact/#contact

### What to Include

Please provide as much information as possible:

- A description of the vulnerability
- Steps to reproduce the issue
- Potential impact and severity assessment
- Any suggested fixes or mitigations

### Response Timeline

- You will receive an acknowledgment within 2 business days
- The security team will investigate and provide an initial assessment within 5 business days
- Updates on remediation progress will be provided as appropriate

## Disclosure Policy

- Security issues are disclosed publicly only after patches are available
- Credit will be given to security researchers who responsibly disclose vulnerabilities
- CVE identifiers will be assigned for confirmed vulnerabilities when appropriate

## Security Best Practices

When deploying Parsec:

1. **TLS Configuration**: Always configure TLS for production gRPC and HTTP endpoints
2. **Network Policies**: Restrict network access to Parsec services using Kubernetes network policies or firewall rules
3. **Authentication**: Use strong authentication mechanisms (mTLS, JWT with strong signing keys)
4. **Regular Updates**: Keep Parsec and its dependencies up to date
5. **Least Privilege**: Run Parsec containers with minimal required privileges
6. **Secret Management**: Use secure secret management solutions (e.g., Kubernetes Secrets, HashiCorp Vault)
7. **Monitoring**: Enable audit logging and monitor for suspicious activity

## Security Scanning

This project uses:

- **OpenSSF Scorecard**: Automated security posture assessment
- **CodeQL**: Static analysis for security vulnerabilities
- **Dependabot**: Automated dependency vulnerability scanning
- **gosec**: Go security checker for common security issues

## Contact

For general security questions or concerns (non-vulnerability):

- Project maintainers: https://github.com/project-kessel/parsec
- Red Hat Security: https://access.redhat.com/security/

For more information about Red Hat's security practices, visit:
https://access.redhat.com/security/
