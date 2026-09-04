# Security Policy

## Supported versions

scankit follows semantic versioning. Security fixes are applied to the latest minor
release. Until 1.0, only the most recent tagged version is supported.

| Version | Supported |
|---------|-----------|
| latest `0.1.x` | ✅ |
| older | ❌ |

## Reporting a vulnerability

Please report security issues privately, **not** through public issues.

- Use GitHub's [private vulnerability reporting](https://github.com/stephrobert/scankit/security/advisories/new)
  (Security tab → *Report a vulnerability*), or
- email the maintainer at `robert.stephane.28@gmail.com` with the details and, if
  possible, a minimal reproducer.

You can expect an acknowledgement within **5 business days**. Once a fix is ready we will
coordinate a release and, where appropriate, request a CVE and credit the reporter.

## Scope

scankit is a library: it evaluates OPA/Rego policies over caller-supplied input and
renders findings. It performs no network I/O of its own and executes no input — with one
caveat worth stating plainly, because it was false until 0.2.3: a **policy** handed to
`engine.Evaluate` is third-party code, and OPA used to let it reach the network through a
JSON-Schema `$ref` even after the network builtins were removed. Since 0.2.3 the capability
set denies every host (`AllowNet: []string{}`), and the guard is asserted by counting
requests a witness server receives, not by trusting an error to be raised. Reports about the
engine mishandling untrusted policy input or scan input are in scope; issues in the
consuming products (pepin, pitstop, pavois) belong in their own repositories.
