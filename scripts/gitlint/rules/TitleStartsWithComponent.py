# SPDX-License-Identifier: Apache-2.0

from gitlint.rules import LineRule, RuleViolation, CommitMessageTitle
import re


class TitleStartsWithComponent(LineRule):
    """A rule to enforce valid commit message title

    Valid title format:
    component1[, component2, componentN]: submodule: summary

    Title should have at least one component
    Components are separated by comma+space: ", "
    Components are validated to be in valid_components
    Components list is ended by a colon
    Submodules are not validated

    """

    # A rule MUST have a human friendly name
    name = "title-has-valid-component"

    # A rule MUST have a *unique* id.
    # We recommend starting with UL (for User-defined Line-rule)
    id = "UL1"

    # A line-rule MUST have a target (not required for CommitRules).
    target = CommitMessageTitle

    def validate(self, line, _commit):
        valid_components = (
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
            'gitlint',
            'hypervisor',
            'main',
            'misc',
            'net_gen',
            'net_util',
            'openapi',
            'option_parser',
            'pci',
            'performance-metrics',
            'rate_limiter',
            'README',
            'resources',
            'scripts',
            'seccomp',
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
            'vm-virtio')

        ptrn_title = re.compile(r'^(.+?):\s(.+)$')
        match = ptrn_title.match(line)

        if not match:
            self.log.debug("Invalid commit title {}", line)
            return [RuleViolation(self.id, "Commit title does not comply with "
                                  "rule: 'component: change summary'")]
        components = match.group(1)
        summary = match.group(2)
        self.log.debug(f"\nComponents: {components}\nSummary: {summary}")

        ptrn_components = re.compile(r',\s')
        components_list = re.split(ptrn_components, components)
        self.log.debug("components list: %s" % components_list)

        for component in components_list:
            if component not in valid_components:
                return [RuleViolation(self.id,
                                      f"Invalid component: {component}, "
                                      "\nValid components are: {}".format(
                                          " ".join(valid_components)))]
