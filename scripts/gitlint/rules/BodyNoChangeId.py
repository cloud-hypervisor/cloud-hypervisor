# SPDX-License-Identifier: Apache-2.0

from gitlint.rules import LineRule, RuleViolation, CommitMessageBody
import re


class BodyNoChangeId(LineRule):
    """Reject Gerrit Change-Id metadata in commit messages."""

    name = "body-no-change-id"
    id = "UL-change-id"
    target = CommitMessageBody

    def validate(self, line, _commit):
        if re.match(r"^\s*Change-Id\s*:", line, re.IGNORECASE):
            return [RuleViolation(self.id, "Remove the Gerrit Change-Id trailer")]
