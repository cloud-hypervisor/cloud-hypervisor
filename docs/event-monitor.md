# Event Monitor

Cloud Hypervisor offers an event monitor which is intended as machine readable
text format for management software to learn about the state of the VMM or the
outcome of certain actions.

## Format

It is a sequence of pretty-printed JSON objects, separated by blank lines. The
timestamp is the duration elapsed since the VMM started.

```json
{
  "timestamp": {
    "secs": 0,
    "nanos": 1693039
  },
  "source": "vmm",
  "event": "starting",
  "properties": null
}

{
  "timestamp": {
    "secs": 0,
    "nanos": 4324467
  },
  "source": "vm",
  "event": "booting",
  "properties": null
}

{
  "timestamp": {
    "secs": 6,
    "nanos": 691500686
  },
  "source": "vm",
  "event": "booted",
  "properties": null
}

{
  "timestamp": {
    "secs": 7,
    "nanos": 611037580
  },
  "source": "virtio-device",
  "event": "activated",
  "properties": {
    "id": "__console"
  }
}

{
  "timestamp": {
    "secs": 7,
    "nanos": 613919623
  },
  "source": "virtio-device",
  "event": "activated",
  "properties": {
    "id": "__rng"
  }
}

...
```

## Configuration

- `--event-monitor path=/tmp/events.txt`
- `--event-monitor fd=23` (if CH inherits FD 23 when spawned)

## Events

An event identifier combines its `source` and `event` fields, written below as
`source.event`.

- `guest.panic`: Guest reported a panic event.
  - Property `event`: Guest panic event.
- `vdpa.activated`: vDPA device was activated.
  - Property `id`: Device identifier.
- `vdpa.reset`: vDPA device was reset.
  - Property `id`: Device identifier.
- `virtio-device.activated`: Virtio device was activated.
  - Property `id`: Device identifier.
- `virtio-device.reset`: Virtio device was reset.
  - Property `id`: Device identifier.
- `vm.booted`: VM boot completed.
- `vm.booting`: VM boot started.
- `vm.coredumping`: VM core dump started.
- `vm.deleted`: VM was deleted.
- `vm.device-removed`: PCI device was removed.
  - Property `id`: Device identifier.
  - Property `bdf`: Device PCI BDF.
- `vm.migration-failed`: Sending migration failed.
- `vm.migration-finished`: Sending migration completed.
- `vm.migration-memory-iteration`: Precopy iteration completed.
  - Property `id`: Precopy iteration number.
- `vm.migration-receive-failed`: Receiving migration failed.
- `vm.migration-receive-finished`: Receiving migration completed.
- `vm.migration-receive-ready`: Migration listener is ready.
- `vm.migration-receive-started`: Migration start request was acknowledged.
- `vm.migration-receive-starting`: Migration connection was accepted.
- `vm.migration-started`: Receiver acknowledged migration start.
- `vm.migration-starting`: Sending migration started.
- `vm.paused`: VM pause completed.
- `vm.pausing`: VM pause started.
- `vm.postcopy-migration-completed`: Postcopy migration completed.
- `vm.rebooted`: VM reboot completed.
- `vm.rebooting`: VM reboot started.
- `vm.resized`: VM resize completed.
- `vm.resizing`: VM resize started.
- `vm.restored`: VM restore completed.
- `vm.restoring`: VM restore started.
- `vm.resumed`: VM resume completed.
- `vm.resuming`: VM resume started.
- `vm.shutdown`: VM shut down.
- `vm.snapshotted`: VM snapshot completed.
- `vm.snapshotting`: VM snapshot started.
- `vmm.shutdown`: VMM shut down.
- `vmm.started`: VMM startup completed and ready to serve API requests.
- `vmm.starting`: VMM startup started.
