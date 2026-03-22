# Cloud Hypervisor Security Policy

Cloud Hypervisor's threat model is in [docs/threat-model.md](docs/threat-model.md).
A vulnerability is defined as an entity defined in the threat model as
untrusted being able to cause Cloud Hypervisor to do something that the
threat model states it should not be able to cause.

Any known or potential memory corruption is assumed exploitable until
and unless proven otherwise. Attackers have shown repeatedly that memory
corruption can usually be turned into arbitrary code execution. While
doing so may be very difficult, LLMs have made this much easier.

Vulnerabilities should be reported using the GitHub Security Advisory
process. Do not file an issue, as that immediately gives malicious
actors knowledge of the vulnerability. A proof of concept is strongly
preferred but not strictly required. A patch is also greatly
appreciated but is also not a requirement.

Cloud Hypervisor does not currently have any bug bounty program.

The use of automated tooling to find vulnerabilities is encouraged.
This includes large language models and other forms of AI. The tool used
should be noted in the report. The human making the report is
responsible for its contents and for filtering out false positives. As
an exception, reports from Miri, Valgrind, or sanitizers can generally
be assumed correct.

It is not expected that every single report will be valid, but reporters
must make a good-faith effort to avoid false positives.

### Special Notes For Reviewers

Cloud Hypervisor does not free guest memory, except after all devices are
shut down. This has been a source of false positives from manual code
review in the past. Code that depends on this fact is still unsound and
should be fixed.

Denial of service attacks are not considered vulnerabilities unless they
can be triggered remotely, such as by malicious network traffic.
