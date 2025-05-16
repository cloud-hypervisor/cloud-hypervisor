# SPDX-License-Identifier: Apache-2.0

from gitlint.rules import LineRule, RuleViolation, CommitMessageBody
import re


class BodyMaxLineLengthEx(LineRule):
    """A rule to enforce a line limit of 72 characters, except for valid cases."""

    # A rule MUST have a human friendly name
    name = "body-max-line-length-ex"

    # A rule MUST have a *unique* id.
    # We recommend starting with UL (for User-defined Line-rule)
    id = "UL-ll"

    # A line-rule MUST have a target (not required for CommitRules).
    target = CommitMessageBody

    max_len = 72

    # Updated property as the commit messages is validated line by line.
    inside_open_codeblock = False

    def validate(self, line, commit):
        # Pattern allowing:
        # - [0]: https://foobar
        # - [0] https://foobar
        # - https://foobar
        link_regex = re.compile(r"^((\[[0-9]+\]:?\s?)?https?:\/\/).*$")

        is_codeblock_marker = line.startswith("```")

        inside_open_codeblock_ = self.inside_open_codeblock
        if is_codeblock_marker:
            self.inside_open_codeblock = not self.inside_open_codeblock

        if len(line) > self.max_len:
            is_link = link_regex.match(line)

            if inside_open_codeblock_:
                return

            if is_link:
                return

            return [
                RuleViolation(self.id, f"Line '{line}' exceeds limit of {self.max_len}")
            ]
