# SPDX-License-Identifier: Apache-2.0

from gitlint.rules import LineRule, RuleViolation, CommitMessageBody
from typing import List, Optional
import re


IGNORE_PREFIXES = [
    # Please sort alphabetically
    " ",
    "Acked-by: ",
    "Co-authored-by: ",
    "Co-developed-by: ",
    "Debugged-by: ",
    "Diagnosed-by: ",
    "Explained-by: ",
    "Fixed-by: ",
    "Fixes: ",
    "Helped-by: ",
    "Inspired-by: ",
    "On-behalf-of: ",
    "Originally-by: ",
    "Reported-by: ",
    "Reviewed-and-tested-by: ",
    "Reviewed-by: ",
    "Signed-off-by: ",
    "Suggested-by: ",
    "Tested-by: ",
    "Triggered-by: ",
    "\t",
]

# Pattern allowing:
# - [0]: https://example.com
# - [0] https://example.com
# - https://example.com
LINK_REGEX = re.compile(r"^(([\[0-9]+]:?\s?)?https?://).*$")

MAX_LEN = 72


class BodyMaxLineLengthEx(LineRule):
    """
    A rule to enforce a line limit of 72 characters, except for valid cases:

    - Markdown-style code blocks
    - Commit tags, such as Signed-off-by
    - Links
    """

    # A rule MUST have a human friendly name
    name = "body-max-line-length-ex"

    # A rule MUST have a *unique* id.
    # We recommend starting with UL (for User-defined Line-rule)
    id = "UL-ll"

    # A line-rule MUST have a target (not required for CommitRules).
    target = CommitMessageBody

    # Updated property as the commit messages is validated line by line.
    inside_open_codeblock = False

    def validate(self, line, commit) -> Optional[List[RuleViolation]]:
        # We keep track of whether we are in an open code block.
        is_codeblock_marker = line.startswith("```")
        inside_open_codeblock_ = self.inside_open_codeblock
        if is_codeblock_marker:
            self.inside_open_codeblock = not self.inside_open_codeblock

        # Begin checks
        if len(line) <= MAX_LEN:
            return None

        if inside_open_codeblock_:
            return None

        if None is not LINK_REGEX.match(line):
            return None

        # Don't check lines with allowed prefixes
        for prefix in IGNORE_PREFIXES:
            if line.startswith(prefix):
                return None

        return [
            RuleViolation(
                self.id,
                f"Line '{line}' exceeds limit of {MAX_LEN}: {len(line)}",
            )
        ]
