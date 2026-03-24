# Contributing to Cloud Hypervisor

Cloud Hypervisor is an open source project licensed under the [Apache v2
License](https://opensource.org/licenses/Apache-2.0) and the [BSD 3
Clause](https://opensource.org/licenses/BSD-3-Clause) license. Individual files
contain details of their licensing and changes to that file are under the same
license unless the contribution changes the license of the file. When importing
code from a third party project (e.g. Firecracker or crosvm) please respect the
license of those projects.

New code should be under the [Apache v2
License](https://opensource.org/licenses/Apache-2.0).

## Coding Style

We follow the [Rust Style](https://github.com/rust-lang/rust/tree/HEAD/src/doc/style-guide/src)
convention and enforce it through the Continuous Integration (CI) process calling into `rustfmt`,
`clippy`, and other well-known code quality tool of the ecosystem for each submitted Pull Request (PR).

## Basic Checks

```sh
# We currently rely on nightly-only formatting features
cargo +nightly fmt --all 
cargo check --all-targets --tests
cargo clippy --all-targets --tests
# Please note that this will not execute integration tests.
cargo test --all-targets --tests

# To lint your last three commits
gitlint --commits "HEAD~3..HEAD"
```

### \[Optional\] Run Integration Tests

_Caution: These tests are taking a long time to complete (40+ mins) and need special setup._

```sh
 bash ./scripts/dev_cli.sh tests --integration -- --test-filter '<optionally filter test by name pattern>' 
```

### Setup Commit Hook

Please consider creating the following hook as `.git/hooks/pre-commit` in order
to ensure basic correctness of your code. You can extend this further if you
have specific features that you regularly develop against.

```sh
#!/bin/sh

cargo +nightly fmt --all -- --check || exit 1
cargo check --locked --all-targets --tests || exit 1
cargo clippy --locked --all-targets --tests -- -D warnings || exit 1
```

You will need to `chmod +x .git/hooks/pre-commit` to have it run on every
commit you make.

## Certificate of Origin

In order to get a clear contribution chain of trust we use the [signed-off-by language](https://www.kernel.org/doc/Documentation/process/submitting-patches.rst)
used by the Linux kernel project.

## Patch format & Git Commit Hygiene

_We use **Patch** as synonym for **Commit**._

We require patches to:

- Have a `Signed-off-by: Name <email>` footer
- Follow the pattern: \
  ```
   <component>: Change summary
   
   More detailed explanation of your changes: Why and how.
   Wrap it to 72 characters.
   See http://chris.beams.io/posts/git-commit/
   for some more good pieces of advice.
   
   Signed-off-by: <contributor@foo.com>
   ```
  

Valid components are listed in `TitleStartsWithComponent.py`. In short, each
cargo workspace member is a valid component as well as `build`, `ci`, `docs` and 
`misc`.

Example patch:

```
vm-virtio: Reset underlying device on driver request
    
If the driver triggers a reset by writing zero into the status register
then reset the underlying device if supported. A device reset also
requires resetting various aspects of the queue.
    
In order to be able to do a subsequent reactivate it is required to
reclaim certain resources (interrupt and queue EventFDs.) If a device
reset is requested by the driver but the underlying device does not
support it then generate an error as the driver would not be able to
configure it anyway.
    
Signed-off-by: Rob Bradford <robert.bradford@intel.com>
```

### Git Commit History

We value a clean, **reviewable** commit history. Each commit should represent
a self-contained, logical step that guides reviewers clearly from A to B.

Avoid patterns like `init A -> init B -> fix A` or \
`init design A -> revert A -> use design B`. Commits must be independently 
reviewable - don't leave "fix previous commit" or earlier design attempts in
the history.

Intermediate work-in-progress changes are acceptable only if a subsequent 
commit in the same series cleans them up (e.g. a temporary `#[allow(unused)]`
removed in the next commit).

## Pull requests

Cloud Hypervisor uses the “fork-and-pull” development model. Follow these steps if
you want to merge your changes to `cloud-hypervisor`:

1. Fork the [cloud-hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor) project
   into your github organization.
1. Within your fork, create a branch for your contribution.
1. [Create a pull request](https://help.github.com/articles/creating-a-pull-request-from-a-fork/)
   against the main branch of the Cloud Hypervisor repository.
1. Each commit must comply with the Commit Hygiene guidelines above.
1. A pull request should address a single component or concern to keep review
   focused and approvals straightforward.
1. Once the pull request is approved it can be integrated.

Please squash any changes done during review already into the corresponding
commits instead of pushing `<component>: addressing review for A`-style commits.

## Issue tracking

If you have a problem, please let us know. We recommend using
[github issues](https://github.com/cloud-hypervisor/cloud-hypervisor/issues/new) for formally
reporting and documenting them.

To quickly and informally bring something up to us, you can also reach out on [Slack](https://cloud-hypervisor.slack.com).

## Closing issues

You can either close issues manually by adding the fixing commit SHA1 to the issue
comments or by adding the `Fixes` keyword to your commit message:

```
serial: Set terminal in raw mode
    
In order to have proper output from the serial, we need to setup the
terminal in raw mode. When the VM is shutting down, it is also the
VMM responsibility to set the terminal back into canonical mode if we
don't want to get any weird behavior from the shell.
    
Fixes #88
	
Signed-off-by: Sebastien Boeuf <sebastien.boeuf@intel.com>
```

Then, after the corresponding PR is merged, GitHub will automatically close that issue when parsing the
[commit message](https://help.github.com/articles/closing-issues-via-commit-messages/).

## AI/LLM Assistance & Generated Code

We recommend **a careful and conservative approach** to LLM usage, guided by
sound engineering judgment. Please use AI/LLM-assisted tooling thoughtfully and
responsibly to ensure efficient use of limited project resources, particularly
in code review and long-term maintenance. Our primary goals are to avoid
ambiguity in license compliance and to keep contributions clear and easy to
review.

Or in other words: please apply common sense and don't blindly accept LLM
suggestions.

This policy can be revisited as LLMs evolve and mature.

### Code Review

We generally recommend doing early coarse-grained reviews using state-of-the-art
LLMs. This can help identify rough edges, copy & paste errors, and typos early
on. This reduces review cycles for human reviewers.

Please **do not** use GitHub Copilot directly in PRs to keep discussions clean.
Instead, ask an LLM of your choice for a review. A convenient way to do this is

- appending `.patch` to the GitHub PR URL
  (e.g., `https://github.com/cloud-hypervisor/cloud-hypervisor/pull/1234.patch`)
  and pasting it into the LLM of your choice, or
- using a local agent in your terminal, such as `codex` or `claude`.

### Contributions assisted by LLMs

All contributions **must** be submitted by a human contributor. Automated or
bot-driven PRs are not accepted.

You are responsible for every piece of code you submit, and you must understand
both the design and the implementation details. LLMs are useful for prototyping
and generating boilerplate code. However, large or complex logic must be
authored and fully understood by the contributor - LLM output should not be
submitted without careful review and comprehension.

Please disclose LLM use in your commit message and PR description if it
meaningfully contributed to the submitted code. Again, we recommend careful and
conservative use of LLMs, guided by common sense.

Maintainers reserve the right to request additional clarification or decline
contributions where LLM usage raises concerns. Ultimately, acceptance of any
contribution is at the maintainers' discretion.
