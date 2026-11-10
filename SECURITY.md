# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| `0.3.x` | Yes |
| `< 0.3` | No |
| `main` | Development |

## Reporting a vulnerability

Use GitHub private vulnerability reporting:

https://github.com/uint82/syscall-engine/security/advisories/new

Do not open a public issue for a suspected vulnerability. Include the affected version, the platform, a reproduction, the impact, and any suggested fix. If private reporting is unavailable, contact [the maintainer](https://github.com/uint82) through GitHub.

## Response process

- Acknowledge within 3 business days.
- Triage within 7 business days.
- Fix or mitigation plan within 30 days for confirmed issues.
- Coordinate disclosure with the reporter. The default window is 90 days.

These are best-effort targets for a personal project, not a service-level agreement.

## Scope

In scope:

- Memory safety and undefined behavior in the library.
- Incorrect SSN resolution or stub assembly.
- Lifecycle, caching, and commit bugs.
- Build, package, and install issues.
- Privilege boundary issues in the library.

Out of scope:

- Detection bypass limitations. The engine is an evasion component; "EDR detects it" is expected and documented in [`docs/security-posture.md`](docs/security-posture.md).
- AV or EDR detections of compiled loaders.
- Missing features or roadmap items.
- Vulnerabilities in payloads or tooling built with the library.
- Social engineering and third-party dependencies.

## Safe harbor

We support good-faith security research. Do not test on systems you do not own or have explicit permission to test. We will not pursue legal action for good-faith research that follows this policy, to the extent permitted by law. This policy does not authorize testing against third-party systems.

## Authorized use

The library is for authorized red teaming, EDR validation, and Windows internals research. You are responsible for compliance with applicable laws, contracts, and rules of engagement. See [`docs/security-posture.md`](docs/security-posture.md) for technical scope and detection notes.

## Bug bounty

This is a personal project. There is no bug bounty.
