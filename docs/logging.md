# Logging

The target audience of this document is both:

- Developers who want to understand what log level to use and when,
- Users who want to debug issues with running their workloads in Cloud Hypervisor

## Control

The number of `-v` parameters passed to the `cloud-hypervisor` binary will determine the log level. Currently the default is log messages up to `WARN:` (`warn!`) are included by default. The `--log-file` allows the log to be sent to a location other than `stderr`.

## Levels

### `error!()`

For any user-initiated action that cannot be carried out as expected, as
well as serious or fatal conditions within the VMM itself. This covers two
cases:

- A requested operation fails with material impact, even if Cloud
  Hypervisor can continue running (e.g. a failed device hotplug, live
  migration, snapshot/restore, or resize). From the user's perspective the
  action they asked for did not happen, so it is an error to them.
- An unrecoverable condition where Cloud Hypervisor cannot continue and
  exits with a non-zero code (e.g. conflicting command line options, or a
  required file that is not present).

Users should react by checking their configuration or the requested
operation.

### `warn!()`

For abnormal conditions that neither prevent a user-initiated action nor
seriously impact the VM. These are user-facing and developer-facing
warnings. A typical example is an ineffectual out-of-bounds access that the
VMM safely ignores.

### `info!()`

Use `-v` to enable.

Primarily targeted at operators and users. For important but infrequent
normal conditions, events, and state changes that are meaningful in production. The same message
should not "spam" the logs, and the VM should remain usable when this level
is enabled (e.g. using stdin/stdout while the logs go to stderr).

### `debug!()`

Use `-vv` to enable.

Developer-facing diagnostic information. It is acceptable to repeat the same
message here.

### `trace!()`

Use `-vvv` to enable.

The most verbose level, for very detailed developer-facing information. As
with `debug!()`, repeated messages are acceptable. This level is typically
combined with `--log-file`.

## Format

The `--log-format <FORMAT>` flag controls how each log record is rendered.
`<FORMAT>` is a template string where tokens enclosed in `{...}` are substituted
at log time. Literal `{` and `}` can be escaped as `{{` and `}}`.

The default format is:

```text
cloud-hypervisor: {boottime}s: <{thread}> {level}:{location} -- {msg}
```

### Common tokens

| Token         | Substituted with                                              |
|---------------|---------------------------------------------------------------|
| `{boottime}`  | Seconds since process start (6 decimal places, right-aligned).|
| `{wallclock}` | UTC RFC 3339 (e.g. `2024-01-15T10:30:45.123456Z`).            |
| `{glog}`      | UTC glog timestamp `MMDD HH:MM:SS.uuuuuu`.                    |
| `{localglog}` | Local-time glog timestamp, same shape as `{glog}`.            |
| `{thread}`    | Thread name (`anonymous` if unnamed).                         |
| `{level}`     | Log level word (`ERROR`/`WARN`/`INFO`/`DEBUG`/`TRACE`).       |
| `{levelchar}` | Single-letter glog level: `E`/`W`/`I`/`D`/`T`.                |
| `{location}`  | `file:line`, or the `log` target if unavailable.              |
| `{msg}`       | Formatted log message.                                        |
| `{pid}`       | Process ID.                                                   |
| `{tid}`       | Kernel thread ID (`gettid(2)`).                               |

### Broken-down date/time fields

Each UTC field has a `local`-prefixed variant that uses the system timezone.
All wallclock-derived tokens within a single record refer to the same instant.

| UTC         | Local            | Output                                |
|-------------|------------------|---------------------------------------|
| `{year}`    | `{localyear}`    | 4-digit year.                         |
| `{month}`   | `{localmonth}`   | 2-digit month.                        |
| `{day}`     | `{localday}`     | 2-digit day of month.                 |
| `{hour}`    | `{localhour}`    | 2-digit hour (24h).                   |
| `{minute}`  | `{localminute}`  | 2-digit minute.                       |
| `{second}`  | `{localsecond}`  | 2-digit second.                       |
| `{micros}`  | `{localmicros}`  | 6-digit microseconds.                 |
| `{offset}`  | `{localoffset}`  | Timezone offset (`+00:00` for UTC).   |

### Examples

Glog header `I0521 08:02:15.542701`:

```text
--log-format '{levelchar}{localglog}'
```

Or built from individual fields:

```text
--log-format '{levelchar}{localmonth}{localday} {localhour}:{localminute}:{localsecond}.{localmicros}'
```
