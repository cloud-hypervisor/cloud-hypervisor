// Copyright © 2026 Cloud Hypervisor Contributors
//
// SPDX-License-Identifier: Apache-2.0
//

use std::io::{self, Write};
use std::str::FromStr;
use std::sync::Mutex;
use std::time::Instant;
use std::{mem, process, thread};

use jiff::tz::TimeZone;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Unterminated '{{' in format string")]
    UnterminatedBrace,
    #[error("Unmatched '}}' in format string")]
    UnmatchedBrace,
    #[error("Unknown format token '{{{0}}}'")]
    UnknownToken(String),
}

/// Which time source a date/time field should be read from.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Zone {
    Utc,
    Local,
}

/// An individual broken-down date/time field.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum TimeField {
    Year,
    Month,
    Day,
    Hour,
    Minute,
    Second,
    Micros,
    /// Timezone offset like `-08:00` (always `+00:00` for `Zone::Utc`).
    Offset,
}

enum Token {
    Literal(String),
    BootTime,
    /// Wallclock using RFC 3339 formatting.
    WallClock,
    /// UTC glog-style timestamp (e.g. `0521 08:02:15.542701`).
    Glog,
    /// Local-time glog-style timestamp (e.g. `0521 08:02:15.542701`).
    LocalGlog,
    Pid,
    Tid,
    Thread,
    /// Full level word (e.g. `INFO`).
    Level,
    /// Single-letter level character, glog style (e.g. `I`).
    LevelChar,
    Location,
    Msg,
    /// A broken-down date/time field from either UTC or local wallclock.
    Time(TimeField, Zone),
}

impl FromStr for Token {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Detect `local`-prefixed variants for the broken-down time fields.
        let (name, zone) = match s.strip_prefix("local") {
            Some(rest) => (rest, Zone::Local),
            None => (s, Zone::Utc),
        };

        match name {
            "year" => return Ok(Self::Time(TimeField::Year, zone)),
            "month" => return Ok(Self::Time(TimeField::Month, zone)),
            "day" => return Ok(Self::Time(TimeField::Day, zone)),
            "hour" => return Ok(Self::Time(TimeField::Hour, zone)),
            "minute" => return Ok(Self::Time(TimeField::Minute, zone)),
            "second" => return Ok(Self::Time(TimeField::Second, zone)),
            "micros" => return Ok(Self::Time(TimeField::Micros, zone)),
            "offset" => return Ok(Self::Time(TimeField::Offset, zone)),
            _ => {}
        }

        // Fall back to tokens that don't take a `local` prefix.
        match s {
            "boottime" => Ok(Self::BootTime),
            "wallclock" => Ok(Self::WallClock),
            "glog" => Ok(Self::Glog),
            "localglog" => Ok(Self::LocalGlog),
            "pid" => Ok(Self::Pid),
            "tid" => Ok(Self::Tid),
            "thread" => Ok(Self::Thread),
            "level" => Ok(Self::Level),
            "levelchar" => Ok(Self::LevelChar),
            "location" => Ok(Self::Location),
            "msg" => Ok(Self::Msg),
            _ => Err(Error::UnknownToken(s.to_string())),
        }
    }
}

/// Convert a `log::Level` to its glog single-letter abbreviation.
fn level_char(level: log::Level) -> char {
    match level {
        log::Level::Error => 'E',
        log::Level::Warn => 'W',
        log::Level::Info => 'I',
        log::Level::Debug => 'D',
        log::Level::Trace => 'T',
    }
}

fn write_time_field<W: Write + ?Sized>(
    out: &mut W,
    field: TimeField,
    zoned: &jiff::Zoned,
) -> io::Result<()> {
    match field {
        TimeField::Year => write!(out, "{:04}", zoned.year()),
        TimeField::Month => write!(out, "{:02}", zoned.month()),
        TimeField::Day => write!(out, "{:02}", zoned.day()),
        TimeField::Hour => write!(out, "{:02}", zoned.hour()),
        TimeField::Minute => write!(out, "{:02}", zoned.minute()),
        TimeField::Second => write!(out, "{:02}", zoned.second()),
        TimeField::Micros => write!(out, "{:06}", zoned.subsec_nanosecond() / 1000),
        TimeField::Offset => write!(out, "{}", zoned.strftime("%:z")),
    }
}

fn parse_format(fmt: &str) -> Result<Vec<Token>, Error> {
    let mut tokens = Vec::new();
    let mut literal = String::new();
    let mut chars = fmt.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '{' => {
                if chars.peek() == Some(&'{') {
                    chars.next();
                    literal.push('{');
                    continue;
                }

                if !literal.is_empty() {
                    tokens.push(Token::Literal(mem::take(&mut literal)));
                }

                let mut name = String::new();
                loop {
                    match chars.next() {
                        Some('}') => break,
                        Some(ch) => name.push(ch),
                        None => return Err(Error::UnterminatedBrace),
                    }
                }

                tokens.push(name.parse()?);
            }
            '}' => {
                if chars.peek() == Some(&'}') {
                    chars.next();
                    literal.push('}');
                } else {
                    return Err(Error::UnmatchedBrace);
                }
            }
            _ => literal.push(c),
        }
    }
    if !literal.is_empty() {
        tokens.push(Token::Literal(literal));
    }
    Ok(tokens)
}

pub const DEFAULT_FORMAT: &str =
    "cloud-hypervisor: {boottime}s: <{thread}> {level}:{location} -- {msg}";

pub struct Logger {
    output: Mutex<Box<dyn Write + Send>>,
    start: Instant,
    pid: u32,
    tokens: Vec<Token>,
    // Saving the timezone when Logger is constructed avoids potential seccomp violations when the
    // internal libc timezone cache expires as the affected thread is unpredictable.
    local_tz: TimeZone,
}

impl Logger {
    pub fn new(output: Box<dyn Write + Send>, format: &str) -> Result<Self, Error> {
        Ok(Self {
            output: Mutex::new(output),
            start: Instant::now(),
            pid: process::id(),
            tokens: parse_format(format)?,
            local_tz: TimeZone::try_system().unwrap_or(TimeZone::UTC),
        })
    }
}

impl log::Log for Logger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let duration_s = Instant::now().duration_since(self.start).as_secs_f32();
        // Compute the wallclock timestamps lazily, but at most once per record so
        // that multiple `{hour}`/`{minute}`/`{second}`/etc. fields stay coherent.
        let mut zoned_utc: Option<jiff::Zoned> = None;
        let mut zoned_local: Option<jiff::Zoned> = None;
        let mut out = self.output.lock().unwrap();
        for token in &self.tokens {
            let _ = match token {
                Token::Literal(s) => out.write_all(s.as_bytes()),
                // 10: 6 decimal places + sep => whole seconds in range `0..=999` properly aligned
                Token::BootTime => write!(&mut *out, "{duration_s:>10.6?}"),
                Token::WallClock => {
                    let zoned = zoned_utc
                        .get_or_insert_with(|| jiff::Timestamp::now().to_zoned(TimeZone::UTC));
                    write!(&mut *out, "{:.6}", zoned.timestamp())
                }
                Token::Glog => {
                    let zoned = zoned_utc
                        .get_or_insert_with(|| jiff::Timestamp::now().to_zoned(TimeZone::UTC));
                    write!(&mut *out, "{}", zoned.strftime("%m%d %H:%M:%S%.6f"))
                }
                Token::LocalGlog => {
                    let zoned = zoned_local.get_or_insert_with(|| {
                        jiff::Timestamp::now().to_zoned(self.local_tz.clone())
                    });
                    write!(&mut *out, "{}", zoned.strftime("%m%d %H:%M:%S%.6f"))
                }
                Token::Pid => write!(&mut *out, "{}", self.pid),
                // SAFETY: gettid(2) always succeeds
                Token::Tid => write!(&mut *out, "{}", unsafe { libc::gettid() }),
                Token::Thread => write!(
                    &mut *out,
                    "{}",
                    thread::current().name().unwrap_or("anonymous")
                ),
                Token::Level => write!(&mut *out, "{}", record.level()),
                Token::LevelChar => write!(&mut *out, "{}", level_char(record.level())),
                Token::Location => match (record.file(), record.line()) {
                    (Some(file), Some(line)) => write!(&mut *out, "{file}:{line}"),
                    _ => write!(&mut *out, "{}", record.target()),
                },
                Token::Msg => write!(&mut *out, "{}", record.args()),
                Token::Time(field, zone) => {
                    let zoned = match zone {
                        Zone::Utc => zoned_utc
                            .get_or_insert_with(|| jiff::Timestamp::now().to_zoned(TimeZone::UTC)),
                        Zone::Local => zoned_local.get_or_insert_with(|| {
                            jiff::Timestamp::now().to_zoned(self.local_tz.clone())
                        }),
                    };
                    write_time_field(&mut *out, *field, zoned)
                }
            };
        }
        let _ = out.write_all(b"\r\n");
    }

    fn flush(&self) {}
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::Arc;

    use log::Log;

    use super::*;

    /// A `Write` sink that appends to a shared byte buffer so tests can
    /// inspect what the logger wrote.
    #[derive(Clone, Default)]
    struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

    impl SharedBuffer {
        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl Write for SharedBuffer {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn render(tokens: &[Token]) -> String {
        tokens
            .iter()
            .map(|t| match t {
                Token::Literal(s) => format!("L({s})"),
                Token::BootTime => "B".to_string(),
                Token::WallClock => "W".to_string(),
                Token::Glog => "G".to_string(),
                Token::LocalGlog => "LG".to_string(),
                Token::Pid => "P".to_string(),
                Token::Tid => "I".to_string(),
                Token::Thread => "T".to_string(),
                Token::Level => "V".to_string(),
                Token::LevelChar => "VC".to_string(),
                Token::Location => "O".to_string(),
                Token::Msg => "M".to_string(),
                Token::Time(field, zone) => {
                    let z = match zone {
                        Zone::Utc => "u",
                        Zone::Local => "l",
                    };
                    let f = match field {
                        TimeField::Year => "Y",
                        TimeField::Month => "Mo",
                        TimeField::Day => "D",
                        TimeField::Hour => "H",
                        TimeField::Minute => "Mi",
                        TimeField::Second => "S",
                        TimeField::Micros => "U",
                        TimeField::Offset => "Z",
                    };
                    format!("T({z}:{f})")
                }
            })
            .collect::<Vec<_>>()
            .join("|")
    }

    #[test]
    fn parse_plain_literal() {
        let tokens = parse_format("hello world").unwrap();
        assert_eq!(render(&tokens), "L(hello world)");
    }

    #[test]
    fn parse_empty_string() {
        let tokens = parse_format("").unwrap();
        assert!(tokens.is_empty());
    }

    #[test]
    fn parse_all_known_tokens() {
        let tokens = parse_format(
            "[{boottime}] {wallclock} {glog} {localglog} {pid}/{tid} <{thread}> {level} {levelchar} {location} -- {msg}",
        )
        .unwrap();
        assert_eq!(
            render(&tokens),
            "L([)|B|L(] )|W|L( )|G|L( )|LG|L( )|P|L(/)|I|L( <)|T|L(> )|V|L( )|VC|L( )|O|L( -- )|M"
        );
    }

    #[test]
    fn parse_default_format_succeeds() {
        let tokens = parse_format(DEFAULT_FORMAT).unwrap();
        // Default format has 5 tokens interleaved with literals.
        assert!(tokens.iter().any(|t| matches!(t, Token::BootTime)));
        assert!(tokens.iter().any(|t| matches!(t, Token::Thread)));
        assert!(tokens.iter().any(|t| matches!(t, Token::Level)));
        assert!(tokens.iter().any(|t| matches!(t, Token::Location)));
        assert!(tokens.iter().any(|t| matches!(t, Token::Msg)));
    }

    #[test]
    fn parse_escaped_braces() {
        let tokens = parse_format("{{not-a-token}}").unwrap();
        assert_eq!(render(&tokens), "L({not-a-token})");
    }

    #[test]
    fn parse_escaped_braces_around_token() {
        let tokens = parse_format("{{{level}}}").unwrap();
        assert_eq!(render(&tokens), "L({)|V|L(})");
    }

    #[test]
    fn parse_unterminated_brace_errors() {
        match parse_format("hello {level") {
            Err(Error::UnterminatedBrace) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn parse_unmatched_close_brace_errors() {
        match parse_format("hello }") {
            Err(Error::UnmatchedBrace) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn parse_unknown_token_errors() {
        match parse_format("{nope}") {
            Err(Error::UnknownToken(name)) => assert_eq!(name, "nope"),
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn logger_new_uses_default_format() {
        let buf = SharedBuffer::default();
        let logger = Logger::new(Box::new(buf.clone()), DEFAULT_FORMAT).unwrap();
        // The default format has all 5 dynamic tokens.
        assert_eq!(
            logger
                .tokens
                .iter()
                .filter(|t| !matches!(t, Token::Literal(_)))
                .count(),
            5
        );
    }

    #[test]
    fn logger_enabled_always_true() {
        let buf = SharedBuffer::default();
        let logger = Logger::new(Box::new(buf), DEFAULT_FORMAT).unwrap();
        let metadata = log::Metadata::builder()
            .level(log::Level::Trace)
            .target("anything")
            .build();
        assert!(logger.enabled(&metadata));
    }

    #[test]
    fn logger_writes_expected_fields() {
        let buf = SharedBuffer::default();
        let logger = Logger::new(Box::new(buf.clone()), DEFAULT_FORMAT).unwrap();

        logger.log(
            &log::Record::builder()
                .args(format_args!("hello {}", "world"))
                .level(log::Level::Info)
                .target("unit_test_target")
                .file(Some("foo.rs"))
                .line(Some(42))
                .build(),
        );

        let out = buf.contents();
        assert!(out.starts_with("cloud-hypervisor: "), "got: {out}");
        assert!(out.contains("INFO"), "got: {out}");
        assert!(out.contains("foo.rs:42"), "got: {out}");
        assert!(out.contains("hello world"), "got: {out}");
        assert!(out.ends_with("\r\n"), "got: {out}");
    }

    #[test]
    fn logger_uses_target_when_no_file() {
        let buf = SharedBuffer::default();
        let logger = Logger::new(Box::new(buf.clone()), DEFAULT_FORMAT).unwrap();

        logger.log(
            &log::Record::builder()
                .args(format_args!("no location"))
                .level(log::Level::Warn)
                .target("my_target")
                .file(None)
                .line(None)
                .build(),
        );

        let out = buf.contents();
        assert!(out.contains("my_target"), "got: {out}");
        assert!(!out.contains("foo.rs"), "got: {out}");
    }

    #[test]
    fn logger_wallclock_is_rfc3339() {
        let buf = SharedBuffer::default();
        let logger = Logger::new(Box::new(buf.clone()), "{wallclock}").unwrap();

        logger.log(
            &log::Record::builder()
                .args(format_args!(""))
                .level(log::Level::Info)
                .target("t")
                .build(),
        );

        let out = buf.contents();
        let out = out.trim();
        assert_eq!(out.len(), 27, "got: {out}");
        assert_eq!(&out[4..5], "-", "got: {out}");
        assert_eq!(&out[7..8], "-", "got: {out}");
        assert_eq!(&out[10..11], "T", "got: {out}");
        assert_eq!(&out[13..14], ":", "got: {out}");
        assert_eq!(&out[16..17], ":", "got: {out}");
        assert_eq!(&out[19..20], ".", "got: {out}");
        assert!(out.ends_with('Z'), "got: {out}");
    }

    #[test]
    fn logger_glog_style_output() {
        // `{levelchar}{localglog}` => glog-style header like `I0521 08:02:15.542701`.
        let buf = SharedBuffer::default();
        let logger = Logger::new(Box::new(buf.clone()), "{levelchar}{localglog}").unwrap();

        logger.log(
            &log::Record::builder()
                .args(format_args!(""))
                .level(log::Level::Info)
                .target("t")
                .build(),
        );

        let out = buf.contents();
        let out = out.trim();
        // `IMMDD HH:MM:SS.uuuuuu` => 21 chars.
        assert_eq!(out.len(), 21, "got: {out}");
        assert_eq!(&out[0..1], "I", "got: {out}");
        assert_eq!(&out[5..6], " ", "got: {out}");
        assert_eq!(&out[8..9], ":", "got: {out}");
        assert_eq!(&out[11..12], ":", "got: {out}");
        assert_eq!(&out[14..15], ".", "got: {out}");
        // Every non-separator character is an ASCII digit.
        for (i, ch) in out.chars().enumerate() {
            if [0, 5, 8, 11, 14].contains(&i) {
                continue;
            }
            assert!(ch.is_ascii_digit(), "non-digit at {i}: got {out}");
        }
    }

    #[test]
    fn logger_glog_utc_output_shape() {
        // `{glog}` alone produces `MMDD HH:MM:SS.uuuuuu` (20 chars).
        let buf = SharedBuffer::default();
        let logger = Logger::new(Box::new(buf.clone()), "{glog}").unwrap();

        logger.log(
            &log::Record::builder()
                .args(format_args!(""))
                .level(log::Level::Info)
                .target("t")
                .build(),
        );

        let out = buf.contents();
        let out = out.trim();
        assert_eq!(out.len(), 20, "got: {out}");
        assert_eq!(&out[4..5], " ", "got: {out}");
        assert_eq!(&out[7..8], ":", "got: {out}");
        assert_eq!(&out[10..11], ":", "got: {out}");
        assert_eq!(&out[13..14], ".", "got: {out}");
    }

    #[test]
    fn parse_utc_time_fields() {
        let tokens =
            parse_format("{year}-{month}-{day}T{hour}:{minute}:{second}.{micros}{offset}").unwrap();
        assert_eq!(
            render(&tokens),
            "T(u:Y)|L(-)|T(u:Mo)|L(-)|T(u:D)|L(T)|T(u:H)|L(:)|T(u:Mi)|L(:)|T(u:S)|L(.)|T(u:U)|T(u:Z)"
        );
    }

    #[test]
    fn parse_local_time_fields() {
        let tokens = parse_format(
            "{localyear}-{localmonth}-{localday}T{localhour}:{localminute}:{localsecond}.{localmicros}{localoffset}",
        )
        .unwrap();
        assert_eq!(
            render(&tokens),
            "T(l:Y)|L(-)|T(l:Mo)|L(-)|T(l:D)|L(T)|T(l:H)|L(:)|T(l:Mi)|L(:)|T(l:S)|L(.)|T(l:U)|T(l:Z)"
        );
    }

    #[test]
    fn logger_utc_offset_is_zero() {
        let buf = SharedBuffer::default();
        let logger = Logger::new(Box::new(buf.clone()), "{offset}").unwrap();
        logger.log(
            &log::Record::builder()
                .args(format_args!(""))
                .level(log::Level::Info)
                .target("t")
                .build(),
        );
        assert_eq!(buf.contents().trim(), "+00:00");
    }

    #[test]
    fn logger_utc_year_matches_jiff() {
        let buf = SharedBuffer::default();
        let logger = Logger::new(Box::new(buf.clone()), "{year}").unwrap();
        logger.log(
            &log::Record::builder()
                .args(format_args!(""))
                .level(log::Level::Info)
                .target("t")
                .build(),
        );
        let year: i32 = buf.contents().trim().parse().expect("year is numeric");
        assert!(year >= 2024, "got: {year}");
    }

    #[test]
    fn logger_levelchar_per_level() {
        for (level, expected) in [
            (log::Level::Error, "E"),
            (log::Level::Warn, "W"),
            (log::Level::Info, "I"),
            (log::Level::Debug, "D"),
            (log::Level::Trace, "T"),
        ] {
            let buf = SharedBuffer::default();
            let logger = Logger::new(Box::new(buf.clone()), "{levelchar}").unwrap();
            logger.log(
                &log::Record::builder()
                    .args(format_args!(""))
                    .level(level)
                    .target("t")
                    .build(),
            );
            assert_eq!(buf.contents().trim(), expected);
        }
    }

    #[test]
    fn logger_pid_token() {
        let buf = SharedBuffer::default();
        let logger = Logger::new(Box::new(buf.clone()), "{pid}").unwrap();

        logger.log(
            &log::Record::builder()
                .args(format_args!(""))
                .level(log::Level::Info)
                .target("t")
                .build(),
        );

        let out = buf.contents();
        let out = out.trim();
        assert_eq!(out, process::id().to_string(), "got: {out}");
    }

    #[test]
    fn logger_tid_token() {
        let buf = SharedBuffer::default();
        let logger = Logger::new(Box::new(buf.clone()), "{tid}").unwrap();

        logger.log(
            &log::Record::builder()
                .args(format_args!(""))
                .level(log::Level::Info)
                .target("t")
                .build(),
        );

        let out = buf.contents();
        let out = out.trim();
        let tid: i64 = out.parse().expect("tid should be numeric");
        assert!(tid > 0, "got: {tid}");
    }

    #[test]
    fn logger_appends_each_record() {
        let buf = SharedBuffer::default();
        let logger = Logger::new(Box::new(buf.clone()), DEFAULT_FORMAT).unwrap();

        for i in 0..3 {
            logger.log(
                &log::Record::builder()
                    .args(format_args!("entry-{i}"))
                    .level(log::Level::Debug)
                    .target("t")
                    .build(),
            );
        }

        let out = buf.contents();
        assert_eq!(out.matches("entry-").count(), 3, "got: {out}");
        assert_eq!(out.matches("\r\n").count(), 3, "got: {out}");
    }
}
