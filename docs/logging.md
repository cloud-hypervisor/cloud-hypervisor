# Logging

The target audience of this document is both:

- Developers who want to understand what log level to use and when,
- Users who want to debug issues with running their workloads in Cloud Hypervisor

## Control

The number of `-v` parameters passed to the `cloud-hypervisor` binary will determine the log level. Currently the default is log messages up to `WARN:` (`warn!`) are included by default. The `--log-file` allows the log to be sent to a location other than `stderr`.

## Levels

### `error!()`

For immediate, unrecoverable errors where it does not make sense for the execution to continue as the behaviour of the VM is considerably impacted.

Cloud Hypervisor should exit shortly after reporting this error (with a non-zero exit code). Generally this should be used during initial construction of the VM state before the virtual CPUs have begun running code.

A typical situation where this might occur is when the user is using command line options that conflict with each other or is trying to use a file that is not present on the filesystem.

Users should react to this error by checking their initial VM configuration.

### `warn!()`

A serious problem has occurred but the execution of the VM can continue although some functionality might be impacted.

A typical example of where this level of message should be generated is during an API call request that cannot be fulfilled.

The user should investigate the meaning of this warning and take steps to ensure the correct functionality.

### `info!()`

Use `-v` to enable.

This level is for the benefit of developers. It should be used for sporadic and infrequent messages. The same message should not "spam" the logs. The VM should be usable when this level of debugging is enabled and trying to use `stdin/stdout` and the logs are going to `stderr`.

### `debug!()`

Use `-vv` to enable.

For the most verbose of logging messages. It is acceptable to "spam" the log with repeated invocations of the same message. This level of logging would be combined with `--log-file`.

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
