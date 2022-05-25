# Cloud Hypervisor Features

Existing cloud hypervisor features and their current phases are described below.

## Features

### Core

| Command Line API | Stable |
| ReST API | Stable |
| TAP Devices | Alpha |
| virtio devices | Alpha  |
| vhost user devices | Alpha |
| VFIO devices | Alpha |
| PCI Passthrough | Alpha |
| Huge Pages (2MiB) | Alpha |
| NUMA | Alpha |
| seccomp | Alpha |
| Snapshot and restore | Alpha |
| Live migration | Alpha |
| Nested virtualization | Alpha |

### Platforms

| x86_64 architecture | Alpha |
| AARCH64  architecture | Alpha |
| Linux KVM Host | Alpha |
| Microsoft Hyper-V Host | Alpha |
| Linux Guests | Alpha |
| Windows Guests | Alpha |

### Guest devices

| Serial port | Alpha |
| RTC/CMOS | Alpha |
| IO APIC | Alpha |
| i8042 shutdown | Alpha |
| ACPI shutdown | Alpha |
| virtio-baloon | Alpha |
| virtio-block | alpha |
| virtio-console | alpha |
| virtio-fs | alpha |
| virtio-iommu | alpha |
| virito-mem | alpha |
| virtio-net | alpha |
| virtio-pmem | Alpha |
| virito-rng | Alpha |
| virtio-vsock | Alpha |
| virtio-watchdog | Alpha |
| vhost-user-blk | Alpha |
| vhost-user-net | Alpha |
| VFIO | Alpha |
| vDPA | Aplha |

### Guest device hotplug

| CPU devices | Alpha |
| PCI devices | Alpha |
| VFIO devices | Alpha |
| virtio devices | Alpha |
| memory | Alpha |
| vDPA devices | Alpha |

### Image formats

| Raw | Alpha |
| Qcow2 | Alpha |
| Fixed VHD | Alpha |
| VHDX | Alpha |

## Feature phase definitions

| Stage | Description |
| --- | --- |
| Experimental | The feature is in development, may not be finalized, and no support guarantees, including API guarantees, are provided. | 
| Alpha | The feature is ready for evaluation, but the maintainers may remove the feature from a future release. | 
| Beta |The feature is ready for production workloads, and some basic support guarantees are made, such as the feature will not be removed in the N-1 (e.g., last LTS release). | 
| Stable | The feature is fialized, documented, tested both unit and functional, and guarantees are made about the API and its associated functionality. The maintainers will announce any feature deprecation with a timeline for removal, e.g., LTS+1 or LTS+2. | 
