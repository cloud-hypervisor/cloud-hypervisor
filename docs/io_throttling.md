# I/O Throttling

Cloud Hypervisor now supports I/O throttling on virtio-block and virtio-net
devices. This support is based on the [`rate-limiter` module](https://github.com/firecracker-microvm/firecracker/tree/7a1231b141e958d15d5b2c079dd5e0880528b4b0/src/rate_limiter)
from Firecracker. This document explains the user interface of this
feature, and highlights some internal implementations that can help users
better understand the expected behavior of I/O throttling in practice.

Cloud Hypervisor allows to limit both the I/O bandwidth (e.g. bytes/s)
and I/O operations (ops/s) independently. For virtio-net devices, while
sharing the same "rate limit" from user inputs (on both bandwidth and
operations), the RX and TX queues are throttled independently.
To limit the I/O bandwidth with a plain token bucket, Cloud Hypervisor
provides three user options, i.e., `bw_size` (bytes), `bw_one_time_burst`
(bytes), and `bw_refill_time` (ms). Both `bw_size` and `bw_refill_time`
are required, while `bw_one_time_burst` is optional.
Internally, these options define a TokenBucket with a maximum capacity
(`bw_size` bytes), an initial burst size (`bw_one_time_burst`) and an
interval for refilling purposes (`bw_refill_time`). The "refill-rate" is
`bw_size` bytes per `bw_refill_time` ms, and it is the constant rate at
which the tokens replenish. The refill process only starts happening
after the initial burst budget is consumed. Without bounded bursts,
consumption from the token bucket is unbounded in speed which allows
for bursts bound in size by the amount of tokens available. Once the
token bucket is empty, consumption speed is bound by the "refill-rate".
Similarly, Cloud Hypervisor provides another three options for limiting
I/O operations, i.e., `ops_size` (I/O operations), `ops_one_time_burst`
(I/O operations), and `ops_refill_time` (ms).

One caveat in plain token-bucket throttling is that every time the bucket
gets empty, it will stop I/O operations for a fixed amount of time
(`cool_down_time`). The `cool_down_time` now is fixed at `100 ms`, it
can have big implications for the actual rate limit (which can be quite
different from the expected "refill-rate" derived from user inputs). For
example, to have a 1000 IOPS limit on a virtio-blk device, users should
be able to provide either of the following two options:
`ops_size=1000,ops_refill_time=1000` or
`ops_size=10,ops_refill_time=10`. However, the actual IOPS limits are
likely to be ~1000 IOPS and ~100 IOPS respectively. The reason is the
actual rate limit users get can be as low as
`ops_size/(ops_refill_time+cool_down_time)`. As a result, it is
generally advisable to keep `bw/ops_refill_time` larger than `100 ms`
(`cool_down_time`) to make sure the actual rate limit is close to users'
expectation ("refill-rate").

## Bounded bursts

Increasing a plain bucket's `size` also increases the credit that can
be consumed at unbounded device speed after idle. Bounded bursts instead
combine a sustained rate with a peak rate and a burst depth.

The following options are available on `--disk`, `--net`, and
`--rate-limit-group`:

- `bw_burst_rate`: peak bandwidth in bytes/s.
- `bw_burst_seconds`: bandwidth burst length in seconds.
- `bw_burst_recharge_seconds`: seconds to regain full bandwidth burst
  credit from empty while idle.
- `ops_burst_rate`: peak rate in operations/s.
- `ops_burst_seconds`: operations burst length in seconds.
- `ops_burst_recharge_seconds`: seconds to regain full operations burst
  credit from empty while idle.

For each token type, the burst length defaults to 1 second when its
burst rate is set. In the JSON API, these are the optional `burst_rate`,
`burst_seconds`, and `burst_recharge_seconds` fields of `TokenBucket`.

With bounded bursts, `size` and `refill_time` only define the sustained
rate `R = size * 1000 / refill_time` in tokens/s (`refill_time` is in ms).
The sustained meter starts full with a depth of `B * T` tokens, where
`B = burst_rate` and `T = burst_seconds`, and by default refills at `R`.
A second, peak meter holds up to `B` tokens and refills at `B`. A request
needs credit from both meters. For requests no larger than `B`, over any
interval of `t` seconds at most `B + B * t` tokens are admitted (and never
more than the sustained meter allows). This is a token-bucket envelope,
not a strict per-second ceiling; request granularity still applies.

In the fluid model, full credit permits `B` for `B * T / (B - R)`
seconds (at least `T`), then consumption is held at `R`. From empty,
full burst credit regenerates after `B * T / R` seconds idle by default.
If `B == R`, there is no rate transition: consumption stays at `R`, with
depth `R * T`.

Set the recharge period `P = burst_recharge_seconds` to change the time
to regain full burst credit from empty while idle. When absent, its
implicit value is `B * T / R`. A shorter period converts only unused
sustained capacity into burst credit faster; under continuous demand
the device is still held at `R`. The base capacity (one second of
sustained rate, rounded up to whole tokens) first refills at `R` before
burst credit accrues. A period longer than the implicit value slows
recharge.
Demand blocked by the limiter (refused or over-consuming requests,
until about 100 ms after the block timer fires) accrues credit only at
`R`; only idle time recharges faster.

The long-term average is at most about `max(R, B * T / P)`, up to token
granularity: faster recharge can increase burst/idle workload averages.

Burst mode requires positive `size`, `refill_time`, `burst_rate`, and
`burst_seconds`, with `burst_rate` at least the sustained rate.
`burst_seconds` and `burst_recharge_seconds` require `burst_rate`.
The recharge period must be longer than the time to refill the base
capacity: about 1 second, but longer for rates below 1 token/s.
Bounded bursts cannot be combined with a nonzero `one_time_burst`.
The burst depth must fit in a 64-bit unsigned integer.

For example, a disk with 5000 IOPS sustained and 20000 IOPS bursts:

```
--disk path=disk.raw,image_type=raw,ops_size=5000,ops_refill_time=1000,ops_burst_rate=20000,ops_burst_seconds=10
```

From full credit this permits approximately 13.3 seconds at 20000 IOPS,
then 5000 IOPS. Full burst credit returns after 40 seconds idle.
Adding `ops_burst_recharge_seconds=20` keeps the same approximately
13.3-second burst, then 5000 IOPS, but restores full credit after
20 seconds idle instead of 40.

A bandwidth burst can also be configured for a group:

```
--rate-limit-group id=group0,bw_size=10485760,bw_refill_time=1000,bw_burst_rate=41943040,bw_burst_seconds=10
```

Group bursts are shared by all member disks. For virtio-net, RX and TX
each get their own burst credit for each queue pair.

## Rate Limit Groups

It is possible to throttle the aggregate bandwidth or operations
of multiple virtio-blk devices using a `rate_limit_group`. virtio-blk devices may be
dynamically added and removed from a `rate_limit_group`. The following example
demonstrates how to throttle the aggregate bandwidth of two disks to 10 MiB/s.

```
--disk path=disk0.raw,rate_limit_group=group0,image_type=raw \
       path=disk1.raw,rate_limit_group=group0,image_type=raw \
--rate-limit-group bw_size=1048576,bw_refill_time=100
```
