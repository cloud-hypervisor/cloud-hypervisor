# Cloud Hypervisor Fork for SAP gardenlinux

The `gardenlinux` branch is the branch from that our SAP colleagues build their
Cloud Hypervisor packages. As our approach is to upstream everything, we expect
to just have PoC code here and revert stuff as we include the merged
functionality from upstream (via rebase or merge, see below).

## Development Model

- Development of all functionality that is upstreamable happens in the original
  Cloud Hypervisor repository.
- Final productization of our Cloud Hypervisor hacking therefore does not happen
  here!
  - The commits are not guaranteed to land as-is in upstream Cloud Hypervisor.
  - Here we only add mostly quashed PoC commits (still in solid shape
    functionality wise and stability wise)
- SAP does not perform `git pull` on this branch, but [pulls][sap-gl-ci] the
  latest state without prior state. Therefore, a precise git history is not
  relevant for them.


[sap-gl-ci]: https://github.com/gardenlinux/package-cloud-hypervisor-gl/blob/main/prepare_source#L1