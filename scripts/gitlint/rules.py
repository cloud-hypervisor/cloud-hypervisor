from gitlint.rules import LineRule, RuleViolation, CommitMessageTitle
import re


class TitleStartsWithComponent(LineRule):
    """This rule will enforce that the commit message title starts with valid
    component name
    """

    # A rule MUST have a human friendly name
    name = "title-has-valid-component"

    # A rule MUST have a *unique* id.
    # We recommend starting with UL (for User-defined Line-rule)
    id = "UL1"

    # A line-rule MUST have a target (not required for CommitRules).
    target = CommitMessageTitle

    def validate(self, line, _commit):
        valid_components = [
            'api_client',
            'arch',
            'block',
            'build',
            'ch-remote',
            'ci',
            'devices',
            'docs',
            'event_monitor',
            'fuzz',
            'github',
            'gitignore',
            'hypervisor',
            'Jenkinsfile',
            'misc',
            'net_gen',
            'net_util',
            'option_parser',
            'pci',
            'performance-metrics',
            'rate_limiter',
            'README',
            'resources',
            'scripts',
            'serial_buffer',
            'test_data',
            'test_infra',
            'tests',
            'tpm',
            'tracer',
            'vhost_user_block',
            'vhost_user_net',
            'virtio-devices',
            'vm-allocator',
            'vm-device',
            'vmm',
            'vm-migration',
            'vm-virtio']

        pattern = re.compile(r'^(.+):\s(.+)$')
        match = pattern.match(line)

        if not match:
            self.log.debug("Invalid commit title {}", line)
            return [RuleViolation(self.id, "Commit title does not comply with "
                                  "rule: 'component: change summary'")]
        component = match.group(1)
        summary = match.group(2)
        self.log.debug(f"\nComponent: {component}\nSummary: {summary}")

        if component not in valid_components:
            return [RuleViolation(self.id,
                                  f"Invalid component: {component}, "
                                  f"valid components are: {valid_components}")]
