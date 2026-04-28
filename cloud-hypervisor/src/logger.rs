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
