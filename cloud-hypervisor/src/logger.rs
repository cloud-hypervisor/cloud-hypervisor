// Copyright © 2026 Cloud Hypervisor Contributors
//
// SPDX-License-Identifier: Apache-2.0
//

use std::io::Write;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::Instant;

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

enum Token {
    Literal(String),
    BootTime,
    Thread,
    Level,
    Location,
    Msg,
}

impl FromStr for Token {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "boottime" => Ok(Self::BootTime),
            "thread" => Ok(Self::Thread),
            "level" => Ok(Self::Level),
            "location" => Ok(Self::Location),
            "msg" => Ok(Self::Msg),
            _ => Err(Error::UnknownToken(s.to_string())),
        }
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
                    tokens.push(Token::Literal(std::mem::take(&mut literal)));
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

const DEFAULT_FORMAT: &str =
    "cloud-hypervisor: {boottime}s: <{thread}> {level}:{location} -- {msg}";

pub struct Logger {
    output: Mutex<Box<dyn Write + Send>>,
    start: Instant,
    tokens: Vec<Token>,
}

impl Logger {
    pub fn new(output: Box<dyn Write + Send>) -> Result<Self, Error> {
        Ok(Self {
            output: Mutex::new(output),
            start: Instant::now(),
            tokens: parse_format(DEFAULT_FORMAT)?,
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
        let mut out = self.output.lock().unwrap();
        for token in &self.tokens {
            let _ = match token {
                Token::Literal(s) => out.write_all(s.as_bytes()),
                // 10: 6 decimal places + sep => whole seconds in range `0..=999` properly aligned
                Token::BootTime => write!(&mut *out, "{duration_s:>10.6?}"),
                Token::Thread => write!(
                    &mut *out,
                    "{}",
                    std::thread::current().name().unwrap_or("anonymous")
                ),
                Token::Level => write!(&mut *out, "{}", record.level()),
                Token::Location => match (record.file(), record.line()) {
                    (Some(file), Some(line)) => write!(&mut *out, "{file}:{line}"),
                    _ => write!(&mut *out, "{}", record.target()),
                },
                Token::Msg => write!(&mut *out, "{}", record.args()),
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
                Token::Thread => "T".to_string(),
                Token::Level => "V".to_string(),
                Token::Location => "O".to_string(),
                Token::Msg => "M".to_string(),
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
        let tokens = parse_format("[{boottime}] <{thread}> {level} {location} -- {msg}").unwrap();
        assert_eq!(render(&tokens), "L([)|B|L(] <)|T|L(> )|V|L( )|O|L( -- )|M");
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
        let logger = Logger::new(Box::new(buf.clone())).unwrap();
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
        let logger = Logger::new(Box::new(buf)).unwrap();
        let metadata = log::Metadata::builder()
            .level(log::Level::Trace)
            .target("anything")
            .build();
        assert!(logger.enabled(&metadata));
    }

    #[test]
    fn logger_writes_expected_fields() {
        let buf = SharedBuffer::default();
        let logger = Logger::new(Box::new(buf.clone())).unwrap();

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
        let logger = Logger::new(Box::new(buf.clone())).unwrap();

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
    fn logger_appends_each_record() {
        let buf = SharedBuffer::default();
        let logger = Logger::new(Box::new(buf.clone())).unwrap();

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
