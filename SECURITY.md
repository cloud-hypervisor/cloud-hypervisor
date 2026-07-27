# Cloud Hypervisor Security Policy

## What Is A Vulnerability?

Cloud Hypervisor's threat model is in [docs/threat-model.md](docs/threat-model.md).
A vulnerability is defined as an entity defined in the threat model as
untrusted being able to cause Cloud Hypervisor to do something that the
threat model states it should not be able to cause.

Any known or potential memory corruption is assumed exploitable until
and unless proven otherwise. Attackers have shown repeatedly that memory
corruption can usually be turned into arbitrary code execution. While
doing so may be very difficult, LLMs have made this much easier.

Mishandling of a memory allocation failure (either user-mode or
kernel-mode) is still in scope.  While this will typically result in
Cloud Hypervisor crashing, Cloud Hypervisor must not corrupt its own
memory or otherwise behave insecurely.

## How To Report A Vulnerability?

Vulnerabilities should be reported using the GitHub Security Advisory
process. Do not file an issue, as that immediately gives malicious
actors knowledge of the vulnerability. A proof of concept is strongly
preferred but not strictly required. A patch is also greatly
appreciated but is also not a requirement.

Cloud Hypervisor does not currently have any bug bounty program.

The use of automated tooling to find vulnerabilities is encouraged.
This includes large language models and other forms of AI. The tool used
should be noted in the report. The human making the report is
responsible for its contents and for filtering out false positives.

It is not expected that every single report will be valid, but reporters
must make a good-faith effort to avoid false positives. Striving to achieve a
zero false-positive rate will reduce the number of correct reports and is not
worthwhile.

## When A Vulnerability Is Reported

The Cloud Hypervisor maintainers will triage any reported
vulnerabilities.  Once patches are ready, an embargo period of up to 14
days starts.  There will be a public announcement that a vulnerability
is under embargo, along with its GHSA number.

The following organizations will receive full access to embargoed
information. They are only permitted to use this information for
preparing and deploying patches. Information must be limited to those
who need to know. This includes access to both patched source code and
patched binaries.

- Microsoft
- Crusoe
- Cyberus Technology
- Meta
- Google
- UbiCloud

This list may be extended by filing a PR.  It will only include:

- Organizations that distribute Cloud Hypervisor to a significant number
  of users.

- Organizations that use Cloud Hypervisor to provide a managed service
  to a significant number of users.

The list is documented here for the purposes of transparency.
