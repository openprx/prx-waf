# Security Policy

prx-waf is a web application firewall. A flaw in it is not just a flaw in one
service — it is a flaw in whatever that service was supposed to protect. We
treat security reports as the highest-priority work in the project and we
commit to the response times below.

## Supported Versions

prx-waf is pre-1.0. Security fixes land on `main` and are shipped as a new
patch release of the current minor series. We do not backport to older minor
series.

| Version | Supported          | Notes                                                     |
| ------- | ------------------ | --------------------------------------------------------- |
| 0.2.x   | :white_check_mark: | Current series. Fixes ship as a new `0.2.z` patch release. |
| 0.1.x   | :x:                | Upgrade to 0.2.x.                                          |
| 0.0.x   | :x:                | Pre-release, never supported.                              |

If you run a fork or a vendored build, you are responsible for rebasing the
fix. We will tell you exactly which commits carry it.

## Reporting a Vulnerability

**Do not open a public issue, pull request, or discussion for a security
problem.**

Report privately through GitHub Security Advisories:

**https://github.com/openprx/prx-waf/security/advisories/new**

This creates a private thread visible only to you and the maintainers, and it
is the only channel we monitor for embargoed reports.

A useful report contains:

- Affected version or commit SHA, and the target triple / OS you ran.
- The relevant parts of your `configs/*.toml` and any custom rules in `rules/`,
  with secrets removed.
- A minimal, self-contained proof of concept — for a detection bypass, the raw
  HTTP request is usually enough.
- What you believe the impact is, and what an attacker gets out of it.

Write in English or Chinese; both are fine.

### Our commitments

| Stage                | Target                                                                      |
| -------------------- | --------------------------------------------------------------------------- |
| Acknowledgement      | **72 hours** from report — a human confirms receipt and that we are on it.   |
| Initial assessment   | **7 days** — we confirm or dispute the finding and give it a severity.       |
| Fix and disclosure   | **90 days** — coordinated public disclosure, sooner if a fix ships earlier.  |

If we miss a target, the delay is our failure, not a reason for you to stay
quiet — you may disclose after the 90-day window regardless of our progress.
We will ask for an extension only if a fix is genuinely in flight, and only
once.

We keep you in the loop at every stage, and we will share the patch with you
before release so you can confirm it actually closes the issue.

### CVE identifiers

For any confirmed vulnerability with real-world impact we request a CVE through
GitHub (as a CNA) and publish a GitHub Security Advisory. Reporters are
credited by name or handle in the advisory and in `CHANGELOG.md` unless you ask
to stay anonymous. We do not require you to request the CVE yourself; if you
already have one, tell us the ID and we will reference it.

## Scope

### In scope

Anything that lets an attacker get past prx-waf, take it over, or take it down:

- **Detection bypass / evasion** — a request that carries a payload prx-waf
  ships a rule for (SQLi, XSS, RCE, path traversal, SSTI, LDAP injection, …)
  but is not detected. This is the flagship class for a WAF; we want these.
  Include the exact request and the rule you expected to fire.
- **Request smuggling, parser differentials, or normalisation gaps** between
  prx-waf and common upstreams that let a payload reach the origin unfiltered.
- **Authentication or authorisation flaws** in the admin API (`waf-api`) or the
  admin UI — session handling, token validation, privilege escalation between
  roles, IDOR on tenant-scoped resources.
- **Injection into prx-waf itself** — SQL injection in the storage layer,
  command injection, unsafe deserialisation, template injection in rules.
- **Remote crash or unbounded resource consumption** triggered by a single
  well-formed request (an algorithmic-complexity bug, a regex that backtracks
  catastrophically, an allocation driven by an attacker-controlled length).
  A panic in the request path is a security bug in this project, not a
  robustness nit — the project bans `unwrap`/`expect` in production code for
  exactly this reason.
- **Cluster and configuration** — node impersonation, unauthenticated control
  plane operations, secrets leaking into logs, TLS verification being skipped.
- **Supply chain** — a compromised or typosquatted dependency, a build or
  release workflow that can be made to publish an artifact we did not build.

### Out of scope

These will be closed without a fix. Reporting them anyway is not held against
you, but it will not receive a CVE or credit.

- **Volumetric denial of service** — flooding, amplification, or stress testing
  any host, including your own deployment. Rate limits, connection limits, and
  L3/L4 capacity are deployment concerns, not product vulnerabilities. An
  *asymmetric* DoS (one small request, disproportionate cost) is in scope and
  belongs in the list above; raw traffic volume does not.
- **Testing against infrastructure you do not own**, including any host
  operated by the maintainers. Reproduce on your own deployment.
- The **documented default admin credentials** (`admin` / `admin123`) and other
  documented insecure defaults intended for local evaluation. Deployment
  documentation tells operators to change them; a report that they exist is not
  a finding. A report that a *documented hardening step does not actually work*
  is.
- **Missing hardening that has no exploit path** — absent security headers on
  the admin UI, missing SameSite on a non-sensitive cookie, TLS ciphers that
  are merely not preferred, lack of rate limiting on an unauthenticated
  read-only endpoint. Show the impact and it becomes in scope.
- **Vulnerabilities in third-party dependencies with no reachable path in
  prx-waf.** Report those upstream; open a normal public issue here so we can
  bump the dependency. Our `cargo audit` / `cargo deny` gate already tracks
  advisories.
- **Automated scanner output without a working proof of concept**, or reports
  consisting only of a tool's report file.
- **Social engineering, phishing, or physical attacks** against maintainers or
  users.
- **Self-inflicted configuration** — turning off detection, running with
  detection in log-only mode, whitelisting an attacker, or exposing the admin
  API to the internet without authentication, and then reporting the
  consequence.
- Bugs that require an already-root local attacker on the WAF host.

## Safe Harbor

If you make a good-faith effort to follow this policy, we consider your
research **authorised**, and:

- We will not pursue or support any legal action against you, and we will not
  report you to law enforcement, for research conducted under this policy.
- We will not ask a third party to take action against you for it.
- If a third party brings legal action against you for research that complied
  with this policy, we will state publicly that your work was authorised.

Good faith means, concretely: you test only against deployments you own or are
explicitly permitted to test; you stop as soon as you have confirmed the issue
rather than pivoting further; you do not access, modify, exfiltrate, or destroy
data belonging to anyone else; you do not degrade service for other users; and
you keep the finding private until the coordinated disclosure date or 90 days,
whichever comes first.

This safe harbor covers what the prx-waf maintainers can authorise. It does not
override the terms of any third party whose systems you test, and it does not
authorise you to break the law.

## Receiving Security Updates

- Watch the repository for **Security advisories** to be notified of
  advisories as they are published.
- Every release is signed and carries build provenance and an SBOM. Verify
  before you deploy — see [`docs/RELEASING.md`](docs/RELEASING.md) for the
  exact `cosign verify-blob` and `gh attestation verify` commands.
- Security fixes are marked in `CHANGELOG.md` under a `### Security` heading
  with the advisory or CVE ID.
