# Security policy

Crenel is a defensive security tool, so a flaw in Crenel itself matters. Thank
you for reporting one responsibly.

## Reporting a vulnerability

Please do not open a public issue for a security problem. Instead, report it
privately through GitHub: on the repository, open the **Security** tab and choose
**Report a vulnerability** (GitHub private advisories). Include:

- what the issue is and where (file, command, or config),
- a minimal way to reproduce it,
- the impact you expect.

We aim to acknowledge a report within a few days and to agree a disclosure
timeline with you before any public write-up.

## Scope

In scope: the engine (`src/`), the CLI, the SARIF/audit output, the bundled
denylist tooling, and the console (`web/`). Of particular interest:

- a way to make the scoped HTTP client (`src/core/net.ts`) reach a host outside
  `allowedHosts`, or a private/metadata address, or follow a redirect off scope;
- a way to make a check write outside its intended files, or run anything active
  without the `allowActiveTesting` gate;
- a crafted scanned input (a bundle, a response header, a finding field) that
  causes code execution, including via the experimental `claude -p` triage;
- a false "clean" result that hides a proven finding (a fail-open).

Out of scope: findings produced about a target you scan (those are the tool
working as intended), and reports that require a malicious config you wrote
yourself with active testing already enabled against your own host.

## Supported versions

Crenel is pre-1.0; fixes land on the default branch. Pin a commit if you need
stability, and watch releases for security updates.
