# Proposal for an Environment Monitor

## Problem Statement

- There is no reasonable way, that strongly encodes seperation of concerns, to currently manage collections of the
  various storage and network backends, as well as the vmm itself. The building blocks all exist, `ch-remote`,
  `cloud-hypervisor`, and various parts of DPDK/SPDK. Unfortunately they dont exist as one integrated unit.

## Solution

Ths proposal suggests the creation of a new process, that executes `cloud-hypervisor` and `ch-remote`, as well as the various
`SPDK`, `DPDK`, and other backends that are of interest. That process is encoded in the class diagram below called
`EnvironmentMonitor`. Additionally, it might be interesting if `EnvironmentMonitor` were less daemon and more stateless...

```mermaid
classDiagram
    %% An EnvironmentMonitor organizes a collection of VirtualEnvironments for the purposes of organization, such as by NUMA
    class EnvironmentMonitor {
        -string availableMemory
	-string availableCPU
	-string availableGPU
	-string availableGPUMemory
        -List~VirtualEnvironment~ virtualEnvironments
	+AttachVirtualEnvironment(Socket) Error
	+RemoveVirtualEnvironment(Socket) Error
    }
    EnvironmentMonitor "1" --> "0..*" VirtualEnvironment

    %% A virtual environment represents the VMM, its storage backends, and its network backends
    %% This is described for completeness, although this is what `ch-remote` does in a stateless way, and I prefer that.
    class VirtualEnvironment {
	-string CPU
	-string memory
	-Block block
	-GPU GPU
	-GPUMemory GPUMemory
	+AttachCPU(CPU) Error
	+AttachMemory(Memory) Error
	+AttachBlock(Block) Error
	+AttachNetwork(Network) Error
	+CreateCloudHypervisor() Socket
    }
    VirtualEnvironment "1" --> "1" Block
    VirtualEnvironment "1" --> "1" Network
    VirtualEnvironment "1" --> "1" CPU
    VirtualEnvironment "1" --> "1" Memory
    VirtualEnvironment "1" --> "1" GPU
    VirtualEnvironment "1" --> "1" GPUMemory
    VirtualEnvironment "1" --> "1" VirtualEnvironment
    VirtualEnvironment "1" --> "1" Socket

    class Error {
    }
    class Block {
    }
    class Network {
    }
    class CPU {
    }
    class GPU {
    }
    class GPUMemory {
    }
    class Memory {
    }
    class Socket {
        -string name
	-string filename
    }
```
