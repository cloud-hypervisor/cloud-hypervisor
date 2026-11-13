# Cloud Hypervisor API

The Cloud Hypervisor API is made of 2 distinct interfaces:

1. **The External API** This is the user facing API. Users and operators
   can control and manage the Cloud Hypervisor through various options
   including a REST API, a Command Line Interface (CLI) or a D-Bus based API,
   which is not compiled into Cloud Hypervisor by default.

1. **The internal API**, based on [rust's Multi-Producer, Single-Consumer (MPSC)](https://doc.rust-lang.org/std/sync/mpsc/)
   module. This API is used internally by the Cloud Hypervisor threads to
   communicate with each other.

The goal of this document is to describe the Cloud Hypervisor API as a whole,
and to outline how the internal and external APIs are architecturally related.

## External API

### REST API

The Cloud Hypervisor [REST](https://en.wikipedia.org/wiki/Representational_state_transfer)
API triggers VM and VMM specific actions, and as such it is designed as a
collection of RPC-style, static methods.

The API is [OpenAPI 3.0](https://github.com/OAI/OpenAPI-Specification/blob/master/versions/3.0.0.md)
compliant. Please consult the [Cloud Hypervisor OpenAPI Document](https://raw.githubusercontent.com/cloud-hypervisor/cloud-hypervisor/master/vmm/src/api/openapi/cloud-hypervisor.yaml)
for more details about the API payloads and responses.

#### REST API Location and availability

The REST API, if enabled, is available as soon as the Cloud Hypervisor binary is started,
through either a local UNIX socket as given in the Cloud Hypervisor option `--api-socket path=...`
or a fd with `--api-socket fd=...`.

```
$ ./target/debug/cloud-hypervisor --api-socket path=/tmp/cloud-hypervisor.sock
```

#### REST API Endpoints

The endpoints and their request and response bodies are defined in the
[Cloud Hypervisor OpenAPI Document](../vmm/src/api/openapi/cloud-hypervisor.yaml).

The `vmcoredump` action is available exclusively for the `x86_64`
architecture and can be executed only when the `guest_debug` feature is
enabled. Without this feature, the corresponding [REST API](#rest-api) or
[D-Bus API](#d-bus-api) endpoints are not available.

#### REST API Examples

For the following set of examples, we assume Cloud Hypervisor is started with
the REST API available at `/tmp/cloud-hypervisor.sock`:

```
$ ./target/debug/cloud-hypervisor --api-socket /tmp/cloud-hypervisor.sock
```

##### Create a Virtual Machine

We want to create a virtual machine with the following characteristics:

* 4 vCPUs
* 1 GB of RAM
* 1 virtio based networking interface
* Direct kernel boot from a custom Linux kernel located at
  `/opt/clh/kernel/vmlinux-virtio-fs-virtio-iommu`
* Using a Ubuntu image as its root filesystem, located at
  `/opt/clh/images/focal-server-cloudimg-amd64.raw`

```shell
#!/usr/bin/env bash

curl --unix-socket /tmp/cloud-hypervisor.sock -i \
     -X PUT 'http://localhost/api/v1/vm.create'  \
     -H 'Accept: application/json'               \
     -H 'Content-Type: application/json'         \
     -d '{
         "cpus":{"boot_vcpus": 4, "max_vcpus": 4},
         "memory":{"size": 1073741824},
         "payload":{"kernel":"/opt/clh/kernel/vmlinux-virtio-fs-virtio-iommu", "cmdline":"console=ttyS0 console=hvc0 root=/dev/vda1 rw"},
         "disks":[{"path":"/opt/clh/images/focal-server-cloudimg-amd64.raw", "image_type":"Raw"}],
         "rng":{"src":"/dev/urandom"},
         "net":[{"ip":"192.168.10.10", "mask":"255.255.255.0", "mac":"12:34:56:78:90:01"}]
         }'
```

##### Boot a Virtual Machine

Once the VM is created, we can boot it:

```shell
#!/usr/bin/env bash

curl --unix-socket /tmp/cloud-hypervisor.sock -i -X PUT 'http://localhost/api/v1/vm.boot'
```

##### Dump Virtual Machine Information

We can fetch information about any VM as soon as it's created:

```shell
#!/usr/bin/env bash

curl --unix-socket /tmp/cloud-hypervisor.sock -i \
     -X GET 'http://localhost/api/v1/vm.info' \
     -H 'Accept: application/json'
```

##### Get Balloon Statistics

When the running VM has negotiated the virtio-balloon statistics feature, the
most recently reported guest sample can be retrieved with:

```shell
curl --unix-socket /tmp/cloud-hypervisor.sock -i \
     -X GET 'http://localhost/api/v1/vm.balloon-stats' \
     -H 'Accept: application/json'
```

The same request is available through `ch-remote balloon-stats`. Reading the
statistics also requests an asynchronous refresh for the next call. The
`last_update` field is a host-generated UNIX timestamp in milliseconds, or zero
if the guest has not supplied its first sample yet. Unsupported guest
statistics are omitted from the response.

##### Reboot a Virtual Machine

We can reboot a VM that's already booted:

```shell
#!/usr/bin/env bash

curl --unix-socket /tmp/cloud-hypervisor.sock -i -X PUT 'http://localhost/api/v1/vm.reboot'
```

##### Shut a Virtual Machine Down

Once booted, we can shut a VM down from the REST API:

```shell
#!/usr/bin/env bash

curl --unix-socket /tmp/cloud-hypervisor.sock -i -X PUT 'http://localhost/api/v1/vm.shutdown'
```

### D-Bus API

Cloud Hypervisor offers a D-Bus API as an alternative to its REST API. This
D-Bus API fully reflects the functionality of the REST API, exposing the
same group of endpoints. It can be a drop-in replacement since it also
consumes/produces JSON.

In addition, the D-Bus API also exposes events from the event monitor in the
form of a D-Bus signal to which users can subscribe. For more information,
see [D-Bus API Interface](#d-bus-api-interface). More information in the
[event monitor documentation](./event-monitor.md).

#### D-Bus API Location and availability

This feature is not compiled into Cloud Hypervisor by default. Users who
wish to use the D-Bus API must explicitly enable it with the `dbus_api`
feature flag when compiling Cloud Hypervisor.

```sh
$ ./scripts/dev_cli.sh build --release --libc musl -- --features dbus_api
```

Once this feature is enabled, it can be configured with the `--dbus-*` CLI
options. See `cloud-hypervisor --help` for details.

Example invocation:

```sh
$ ./cloud-hypervisor --dbus-service-name "org.cloudhypervisor.DBusApi" \
                     --dbus-object-path "/org/cloudhypervisor/DBusApi"
```

This will start serving a service with the name `org.cloudhypervisor.DBusApi`
and the interface `org.cloudhypervisor.DBusApi1`, which in turn can be used to
control and manage Cloud Hypervisor.

#### D-Bus API Interface

Please refer to the [REST API](#rest-api) documentation for everything that
is in common with the REST API. As previously mentioned, the D-Bus API can
be used as a drop-in replacement for the [REST API](#rest-api).

The D-Bus interface also exposes a signal, named `Event`, which is emitted
whenever a new event is published from the `event-monitor` crate. Here is its
definition in XML format:

```xml
<node>
  <interface name="org.cloudhypervisor.DBusApi1">
    <signal name="Event">
      <arg name="event" type="s"/>
    </signal>
  </interface>
</node>
```

### Command Line Interface

The Cloud Hypervisor Command Line Interface (CLI) can only be used for launching
the Cloud Hypervisor binary, i.e. it cannot be used for controlling the VMM or
the launched VM once they're up and running.

If you want to inspect the VMM, or control the VM after launching Cloud
Hypervisor from the CLI, you must use either the [REST API](#rest-api)
or the [D-Bus API](#d-bus-api).

From the CLI, one can:

1. Create and boot a complete virtual machine by using the CLI options to build
   the VM config. Run `cloud-hypervisor --help` for a complete list of CLI
   options. As soon as the `cloud-hypervisor` binary is launched, contrary
   to the [D-Bus API](#d-bus-api), the [REST API](#rest-api) is available
   for controlling and managing the VM. The [D-Bus API](#d-bus-api) doesn't start
   automatically and needs to be explicitly configured in order to be run.
1. Start either the REST API, D-Bus API or both simultaneously without passing
   any VM configuration options. The VM can then be asynchronously created and
   booted by calling API methods of choice. It should be noted that one external
   API does not exclude another; it is possible to have both the REST and D-Bus
   APIs running simultaneously.

### REST API, D-Bus API and CLI Architectural Relationship

The REST API, D-Bus API and the CLI all rely on a common, [internal API](#internal-api).

The CLI options are parsed by the
[clap crate](https://docs.rs/clap/4.5.53/clap/) and then translated into
[internal API](#internal-api) commands.

The REST API is processed by an HTTP thread using the
[Firecracker's `micro_http`](https://github.com/firecracker-microvm/micro-http)
crate. As with the CLI, the HTTP requests eventually get translated into
[internal API](#internal-api) commands.

The D-Bus API is implemented using the [zbus](https://github.com/dbus2/zbus)
crate and runs in its own thread. Whenever it needs to call the [internal API](#internal-api),
the [blocking](https://github.com/smol-rs/blocking) crate is used to perform the call in zbus' async context.

As a summary, the REST API, the D-Bus API and the CLI are essentially frontends for the
[internal API](#internal-api):

```
                                  +------------------+
                        REST API  |                  |
                       +--------->+    micro_http    +--------+
                       |          |                  |        |
                       |          +------------------+        |
                       |                                      |      +------------------------+
                       |                                      |      |                        |
+------------+         |            +----------+              |      |                        |
|            |         |  D-Bus API |          |              |      | +--------------+       |
|    User    +---------+----------->+   zbus   +--------------+------> | Internal API |       |
|            |         |            |          |              |      | +--------------+       |
+------------+         |            +----------+              |      |                        |
                       |                                      |      |                        |
                       |                                      |      +------------------------+
                       |            +----------+              |                 VMM
                       |     CLI    |          |              |
                       +----------->+   clap   +--------------+
                                    |          |
                                    +----------+


```

## Internal API

The Cloud Hypervisor internal API, as its name suggests, is used internally
by the different Cloud Hypervisor threads (VMM, HTTP, D-Bus, control loop,
etc) to send commands and responses to each other.

It is based on [rust's Multi-Producer, Single-Consumer (MPSC)](https://doc.rust-lang.org/std/sync/mpsc/),
and the single consumer (a.k.a. the API receiver) is the Cloud Hypervisor
control loop.

API producers are the HTTP thread handling the [REST API](#rest-api), the
D-Bus thread handling the [D-Bus API](#d-bus-api) and the main thread that
initially parses the [CLI](#command-line-interface).

### Goals and Design

The internal API is designed for controlling, managing and inspecting a Cloud
Hypervisor VMM and its guest. It is a backend for handling external, user
visible requests through the [REST API](#rest-api), the [D-Bus API](#d-bus-api)
or the [CLI](#command-line-interface) interfaces.

The API follows a command-response scheme that closely maps the [REST API](#rest-api).
Any command must be replied to with a response.

Commands are [MPSC](https://doc.rust-lang.org/std/sync/mpsc/) based messages and
are received and processed by the VMM control loop.

In order for the VMM control loop to respond to any internal API command, it
must be able to send a response back to the MPSC sender. For that purpose, all
internal API command payload carry the [Sender](https://doc.rust-lang.org/std/sync/mpsc/struct.Sender.html)
end of an [MPSC](https://doc.rust-lang.org/std/sync/mpsc/) channel.

The sender of any internal API command is therefore responsible for:

1. Creating an [MPSC](https://doc.rust-lang.org/std/sync/mpsc/) response
   channel.
1. Passing the [Sender](https://doc.rust-lang.org/std/sync/mpsc/struct.Sender.html)
   end of the response channel as part of the internal API command payload.
1. Waiting for the internal API command's response on the [Receiver](https://doc.rust-lang.org/std/sync/mpsc/struct.Receiver.html)
   end of the response channel.

## End to End Example

The following steps show how a `vm.create` request flows through the external
and internal APIs. The other requests follow the same path.

1. A user sends a `PUT /api/v1/vm.create` request with a `VmConfig` JSON body
   to the [REST API](#rest-api) socket.
1. The HTTP thread deserializes the body into a `VmConfig` and calls
   `VmCreate.send()`.
1. `send()` creates a response channel and wraps the request into an
   `ApiRequest` closure that holds the response sender. It sends the closure
   through the API channel and writes to the API `EventFd` to wake up the
   control loop.
1. The control loop receives the closure and runs it. The closure calls
   `vm_create()`, which only stores the configuration. The VM itself is created
   when a `vm.boot` request arrives.
1. The closure sends the result through the response channel. The HTTP thread
   receives it and replies with `204 No Content` on success.
