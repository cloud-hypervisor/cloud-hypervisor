// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! A parser for comma-separated `key=value` option strings.
//!
//! This crate provides [`OptionParser`], which parses strings of the form
//! `"key1=value1,key2=value2,..."` into a set of named options that can then
//! be retrieved and converted to various types.
//!
//! Values may be quoted with `"` to embed commas and other special characters,
//! and brackets `[` `]` are tracked so that list-valued options like
//! `topology=[1,2,3]` are not split at inner commas.
//!
//! # Example
//!
//! ```
//! use option_parser::OptionParser;
//!
//! let mut parser = OptionParser::new();
//! parser.add("size").add("mergeable");
//! parser.parse("size=128M,mergeable=on").unwrap();
//!
//! assert_eq!(parser.get("size"), Some("128M".to_owned()));
//! assert_eq!(parser.get("mergeable"), Some("on".to_owned()));
//! ```

use std::collections::HashMap;
use std::fmt::{self, Display, Write};
use std::num::ParseIntError;
use std::result;
use std::str::FromStr;

use thiserror::Error;

mod private_trait {
    // Voldemort trait that dispatches to `FromStr::from_str` on externally-defined types
    // and to custom parsing code for types in this module.
    pub trait Parseable
    where
        Self: Sized,
    {
        type Err;
        // Actually does the parsing, but panics if the input doesn't have
        // balanced quotes.  This is fine because split_commas checks that the
        // input has balanced quotes, and option names cannot contain anything
        // that split_commas treats as special.
        fn from_str(input: &str) -> Result<Self, <Self as Parseable>::Err>;
    }
}
use private_trait::Parseable;

/// A parser for comma-separated `key=value` option strings.
///
/// Options must be registered with [`add`](Self::add) or
/// [`add_valueless`](Self::add_valueless) before parsing. After calling
/// [`parse`](Self::parse), values can be retrieved with [`get`](Self::get)
/// or converted to a specific type with [`convert`](Self::convert).
#[derive(Default)]
pub struct OptionParser {
    options: HashMap<String, OptionParserValue>,
}

struct OptionParserValue {
    value: Option<String>,
    requires_value: bool,
}

/// Errors returned when parsing or converting options.
#[derive(Debug, Error)]
pub enum OptionParserError {
    /// An option name was not previously registered with [`OptionParser::add`].
    #[error("Unknown option: {0}")]
    UnknownOption(String),
    /// The input string has invalid syntax (unbalanced quotes/brackets, missing `=`).
    #[error("Invalid syntax: {0}")]
    InvalidSyntax(String),
    /// A value could not be converted to the requested type.
    #[error("Unable to convert {1} for {0}")]
    Conversion(String /* field */, String /* value */),
    /// A value was syntactically valid but semantically wrong.
    #[error("Invalid value: {0}")]
    InvalidValue(String),
}
type OptionParserResult<T> = result::Result<T, OptionParserError>;

fn split_commas(s: &str) -> OptionParserResult<Vec<String>> {
    let mut list: Vec<String> = Vec::new();
    let mut opened_brackets = 0u64;
    let mut in_quotes = false;
    let mut current = String::new();

    for c in s.trim().chars() {
        match c {
            // In quotes, only '"' is special
            '"' => in_quotes = !in_quotes,
            _ if in_quotes => {}
            '[' => opened_brackets += 1,
            ']' => {
                if opened_brackets < 1 {
                    return Err(OptionParserError::InvalidSyntax(s.to_owned()));
                }
                opened_brackets -= 1;
            }
            ',' if opened_brackets == 0 => {
                list.push(current);
                current = String::new();
                continue;
            }
            _ => {}
        }
        current.push(c);
    }
    list.push(current);

    if in_quotes || opened_brackets != 0 {
        return Err(OptionParserError::InvalidSyntax(s.to_owned()));
    }

    Ok(list)
}

impl OptionParser {
    /// Creates an empty `OptionParser` with no registered options.
    pub fn new() -> Self {
        Self {
            options: HashMap::new(),
        }
    }

    fn parse_inner(&mut self, input: &str, ignore_unknown: bool) -> OptionParserResult<()> {
        if input.trim().is_empty() {
            return Ok(());
        }

        for option in split_commas(input)?.iter() {
            let parts: Vec<&str> = option.splitn(2, '=').collect();
            match self.options.get_mut(parts[0]) {
                None => {
                    if !ignore_unknown {
                        return Err(OptionParserError::UnknownOption(parts[0].to_owned()));
                    }
                }
                Some(value) => {
                    if value.requires_value {
                        if parts.len() != 2 {
                            return Err(OptionParserError::InvalidSyntax((*option).to_owned()));
                        }
                        value.value = Some(parts[1].trim().to_owned());
                    } else {
                        value.value = Some(String::new());
                    }
                }
            }
        }

        Ok(())
    }

    /// Parses a comma-separated `key=value` string, updating registered options.
    ///
    /// Returns an error if the input contains an unknown option name, has
    /// unbalanced quotes or brackets, or a value-requiring option lacks `=`.
    pub fn parse(&mut self, input: &str) -> OptionParserResult<()> {
        self.parse_inner(input, false)
    }

    /// Like [`parse`](Self::parse), but silently ignores unknown option names.
    ///
    /// This is useful when multiple parsers share the same input string and
    /// each only cares about a subset of the options.
    pub fn parse_subset(&mut self, input: &str) -> OptionParserResult<()> {
        self.parse_inner(input, true)
    }

    /// Registers a named option that requires a value (i.e. `key=value`).
    ///
    /// Option names must not contain `"`, `[`, `]`, `=`, or `,`.
    /// Returns `&mut Self` for chaining.
    ///
    /// # Panics
    ///
    /// Panics if the option name contains a forbidden character.
    pub fn add(&mut self, option: &str) -> &mut Self {
        // Check that option=value has balanced
        // quotes and brackets iff value does.
        assert!(
            !option.contains(['"', '[', ']', '=', ',']),
            "forbidden character in option name"
        );
        self.options.insert(
            option.to_owned(),
            OptionParserValue {
                value: None,
                requires_value: true,
            },
        );

        self
    }

    /// Registers multiple value-requiring options at once.
    ///
    /// Equivalent to calling [`add`](Self::add) for each element in the slice.
    pub fn add_all(&mut self, options: &[&str]) -> &mut Self {
        for option in options {
            self.add(option);
        }

        self
    }

    /// Registers a flag-style option that does not take a value.
    ///
    /// When this option appears in the input string (without `=`), it is
    /// marked as set. Use [`is_set`](Self::is_set) to query it.
    pub fn add_valueless(&mut self, option: &str) -> &mut Self {
        self.options.insert(
            option.to_owned(),
            OptionParserValue {
                value: None,
                requires_value: false,
            },
        );

        self
    }

    /// Registers multiple flag-style options that do not take a value.
    ///
    /// Equivalent to calling [`add_valueless`](Self::add_valueless) for each
    /// element in the slice.
    pub fn add_all_valueless(&mut self, options: &[&str]) -> &mut Self {
        for option in options {
            self.add_valueless(option);
        }
        self
    }

    /// Returns the raw string value of an option, or `None` if the option was
    /// not set or if its value is an empty string (e.g. `key=`).
    ///
    /// Surrounding double-quotes in the value are removed.
    pub fn get(&self, option: &str) -> Option<String> {
        self.options
            .get(option)
            .and_then(|v| v.value.clone())
            .and_then(|s| {
                if s.is_empty() {
                    None
                } else {
                    Some(dequote(&s))
                }
            })
    }

    /// Returns `true` if the option was present in the parsed input.
    ///
    /// This works for both value-requiring and valueless options.
    pub fn is_set(&self, option: &str) -> bool {
        self.options
            .get(option)
            .and_then(|v| v.value.as_ref())
            .is_some()
    }

    /// Retrieves and converts an option value to type `T`.
    ///
    /// Returns `Ok(None)` if the option was not set or its value is empty.
    /// Returns `Err` if the value cannot be converted to `T`.
    ///
    /// `T` can be any type that implements `FromStr` (e.g. `u32`, `String`),
    /// or one of this crate's types such as [`Toggle`], [`IntegerList`],
    /// [`Tuple`], [`TupleList`] or [`StringList`].
    pub fn convert<T: Parseable>(&self, option: &str) -> OptionParserResult<Option<T>> {
        match self.options.get(option).and_then(|v| v.value.as_ref()) {
            None => Ok(None),
            Some(v) => {
                Ok(if v.is_empty() {
                    None
                } else {
                    Some(Parseable::from_str(v).map_err(|_| {
                        OptionParserError::Conversion(option.to_owned(), v.to_owned())
                    })?)
                })
            }
        }
    }
}

/// A boolean-like value that accepts `"on"`, `"true"`, `"off"`, `"false"`, or `""`.
///
/// An empty string is treated as `false`.
pub struct Toggle(pub bool);

#[derive(Error, Debug)]
pub enum ToggleParseError {
    #[error("Invalid value: {0}")]
    InvalidValue(String),
}

impl Parseable for Toggle {
    type Err = ToggleParseError;

    fn from_str(s: &str) -> result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "" => Ok(Toggle(false)),
            "on" => Ok(Toggle(true)),
            "off" => Ok(Toggle(false)),
            "true" => Ok(Toggle(true)),
            "false" => Ok(Toggle(false)),
            _ => Err(ToggleParseError::InvalidValue(s.to_owned())),
        }
    }
}

/// A byte size parsed from a human-readable string with optional `K`, `M`, or `G` suffix.
///
/// The suffix is binary (1K = 1024, 1M = 1048576, 1G = 1073741824).
/// A bare integer is treated as bytes.
pub struct ByteSized(pub u64);

#[derive(Error, Debug)]
pub enum ByteSizedParseError {
    #[error("Invalid value: {0}")]
    InvalidValue(String),
}

impl FromStr for ByteSized {
    type Err = ByteSizedParseError;

    fn from_str(s: &str) -> result::Result<Self, Self::Err> {
        Ok(ByteSized({
            let s = s.trim();
            let shift = if s.ends_with('K') {
                10
            } else if s.ends_with('M') {
                20
            } else if s.ends_with('G') {
                30
            } else {
                0
            };

            let s = s.trim_end_matches(['K', 'M', 'G']);
            s.parse::<u64>()
                .map_err(|_| ByteSizedParseError::InvalidValue(s.to_owned()))?
                << shift
        }))
    }
}

/// A list of integers parsed from a bracket-enclosed, comma-separated string.
///
/// Ranges are supported with `-`: `"[0,2-4,6]"` produces `[0, 2, 3, 4, 6]`.
/// The element type defaults to `u64`. Use e.g `IntegerList<u16>` to parse
/// into a narrower type, which rejects values that do not fit.
pub struct IntegerList<T = u64>(pub Vec<T>);

impl<T: Display> Display for IntegerList<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_char('[')?;
        let mut iter = self.0.iter();
        if let Some(first) = iter.next() {
            first.fmt(f)?;
            for i in iter {
                f.write_char(',')?;
                i.fmt(f)?;
            }
        }
        f.write_char(']')
    }
}

#[derive(Error, Debug)]
pub enum IntegerListParseError {
    #[error("Invalid value: {0}")]
    InvalidValue(String),
}

impl<T: TryFrom<u64>> Parseable for IntegerList<T> {
    type Err = IntegerListParseError;

    fn from_str(s: &str) -> result::Result<Self, Self::Err> {
        let mut integer_list = Vec::new();
        let ranges_list: Vec<&str> = s
            .trim()
            .trim_matches(|c| c == '[' || c == ']')
            .split(',')
            .collect();

        for range in ranges_list.iter() {
            let items: Vec<&str> = range.split('-').collect();

            if items.len() > 2 {
                return Err(IntegerListParseError::InvalidValue((*range).to_string()));
            }

            let start_range = items[0]
                .parse::<u64>()
                .map_err(|_| IntegerListParseError::InvalidValue(items[0].to_owned()))?;

            let end_range = if items.len() == 2 {
                let end_range = items[1]
                    .parse::<u64>()
                    .map_err(|_| IntegerListParseError::InvalidValue(items[1].to_owned()))?;
                if start_range >= end_range {
                    return Err(IntegerListParseError::InvalidValue((*range).to_string()));
                }
                end_range
            } else {
                start_range
            };

            for value in start_range..=end_range {
                let value = T::try_from(value)
                    .map_err(|_| IntegerListParseError::InvalidValue(value.to_string()))?;
                integer_list.push(value);
            }
        }

        Ok(IntegerList(integer_list))
    }
}

/// Types that can appear as the second element of a [`Tuple`] pair.
///
/// Implemented for `u64`, `Vec<u8>`, `Vec<u64>`, and `Vec<usize>`.
pub trait TupleValue {
    /// Parses the value portion of a `key@value` tuple element.
    fn parse_value(input: &str) -> Result<Self, TupleError>
    where
        Self: Sized;
}

impl TupleValue for u64 {
    fn parse_value(input: &str) -> Result<Self, TupleError> {
        input.parse::<u64>().map_err(TupleError::InvalidInteger)
    }
}

impl TupleValue for Vec<u8> {
    fn parse_value(input: &str) -> Result<Self, TupleError> {
        Ok(IntegerList::<u8>::from_str(input)
            .map_err(TupleError::InvalidIntegerList)?
            .0)
    }
}

impl TupleValue for Vec<u64> {
    fn parse_value(input: &str) -> Result<Self, TupleError> {
        Ok(IntegerList::<u64>::from_str(input)
            .map_err(TupleError::InvalidIntegerList)?
            .0)
    }
}

impl TupleValue for Vec<usize> {
    fn parse_value(input: &str) -> Result<Self, TupleError> {
        Ok(IntegerList::<usize>::from_str(input)
            .map_err(TupleError::InvalidIntegerList)?
            .0)
    }
}

#[derive(Error, Debug)]
pub enum TupleError {
    #[error("Invalid value: {0}")]
    InvalidValue(String),
    #[error("Unbalanced brackets in one of the values")]
    SplitInsideBrackets(#[source] OptionParserError),
    #[error("Expected a single pair of enclosing brackets in input: {0}")]
    UnbalancedOutsideBrackets(String),
    #[error("Invalid integer list")]
    InvalidIntegerList(#[source] IntegerListParseError),
    #[error("Invalid integer")]
    InvalidInteger(#[source] ParseIntError),
    #[error("Empty key in tuple: {0}")]
    EmptyKey(String),
}

/// A tuple consisting of a `key@value` pair parsed from a string.
#[derive(PartialEq, Eq, Debug)]
pub struct Tuple<S, T>(pub S, pub T);

/// A list of `key@value` pairs parsed from a bracket-enclosed string.
///
/// The format is `[key1@value1,key2@value2,...]` where `@` separates each
/// pair's elements. `S` is the key type and `T` is the value type.
#[derive(PartialEq, Eq, Debug)]
pub struct TupleList<S, T>(pub Vec<Tuple<S, T>>);

impl<S: Parseable, T: TupleValue> Parseable for Tuple<S, T> {
    type Err = TupleError;

    fn from_str(tuple: &str) -> result::Result<Self, Self::Err> {
        let mut in_quotes = false;
        let mut last_idx = 0;
        let mut first_val = None;
        let trimmed = tuple.trim();
        for (idx, c) in trimmed.as_bytes().iter().enumerate() {
            match c {
                b'"' => in_quotes = !in_quotes,
                b'@' if !in_quotes => {
                    if last_idx != 0 {
                        return Err(TupleError::InvalidValue((*trimmed).to_string()));
                    }
                    let key = &trimmed[last_idx..idx];
                    first_val = if key.is_empty() {
                        return Err(TupleError::EmptyKey((*trimmed).to_string()));
                    } else {
                        Some(key)
                    };
                    last_idx = idx + 1;
                }
                _ => {}
            }
        }
        let item1 = <S as Parseable>::from_str(
            first_val.ok_or(TupleError::InvalidValue((*trimmed).to_string()))?,
        )
        .map_err(|_| TupleError::InvalidValue(first_val.unwrap().to_owned()))?;
        let item2: T = TupleValue::parse_value(&trimmed[last_idx..])?;
        Ok(Tuple(item1, item2))
    }
}

impl<S: Parseable, T: TupleValue> Parseable for TupleList<S, T> {
    type Err = TupleError;

    fn from_str(s: &str) -> result::Result<Self, Self::Err> {
        let mut list: Vec<Tuple<S, T>> = Vec::new();
        let body = s
            .trim()
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .ok_or_else(|| TupleError::UnbalancedOutsideBrackets(s.to_string()))?;
        let tuples_raw = split_commas(body).map_err(TupleError::SplitInsideBrackets)?;
        for tuple_raw in tuples_raw.iter() {
            list.push(Tuple::from_str(tuple_raw.trim())?);
        }

        Ok(TupleList(list))
    }
}

/// A list of strings parsed from a bracket-enclosed, comma-separated string.
///
/// The format is `[str1,str2,...]`. Brackets are optional.
#[derive(Default)]
pub struct StringList(pub Vec<String>);

#[derive(Error, Debug)]
pub enum StringListParseError {
    #[error("Invalid value: {0}")]
    InvalidValue(String),
}

fn dequote(s: &str) -> String {
    let mut prev_byte = b'\0';
    let mut in_quotes = false;
    let mut out: Vec<u8> = vec![];
    for i in s.bytes() {
        if i == b'"' {
            if prev_byte == b'"' && !in_quotes {
                out.push(b'"');
            }
            in_quotes = !in_quotes;
        } else {
            out.push(i);
        }
        prev_byte = i;
    }
    assert!(!in_quotes, "split_commas didn't reject unbalanced quotes");
    // SAFETY: the non-ASCII bytes in the output are the same
    // and in the same order as those in the input, so if the
    // input is valid UTF-8 the output will be as well.
    unsafe { String::from_utf8_unchecked(out) }
}

impl<T> Parseable for T
where
    T: FromStr + Sized,
{
    type Err = <T as FromStr>::Err;
    fn from_str(s: &str) -> result::Result<Self, Self::Err> {
        dequote(s).parse()
    }
}

impl Parseable for StringList {
    type Err = StringListParseError;

    fn from_str(s: &str) -> result::Result<Self, Self::Err> {
        let string_list: Vec<String> =
            split_commas(s.trim().trim_matches(|c| c == '[' || c == ']'))
                .map_err(|_| StringListParseError::InvalidValue(s.to_owned()))?
                .iter()
                .map(|e| e.to_owned())
                .collect();

        Ok(StringList(string_list))
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_option_parser() {
        let mut parser = OptionParser::new();
        parser
            .add("size")
            .add("mergeable")
            .add("hotplug_method")
            .add("hotplug_size")
            .add("topology")
            .add("cmdline");

        assert_eq!(split_commas("\"\"").unwrap(), vec!["\"\""]);
        parser.parse("size=128M,hanging_param").unwrap_err();
        parser.parse("size=128M,file=/dev/shm").unwrap_err();

        // Equals signs within a value are fine (splitn(2, '=') keeps them)
        parser.add("extra");
        parser.parse("extra=foo=bar").unwrap();
        assert_eq!(parser.get("extra"), Some("foo=bar".to_owned()));

        parser.parse("size=128M").unwrap();
        assert_eq!(parser.get("size"), Some("128M".to_owned()));
        assert!(!parser.is_set("mergeable"));
        assert!(parser.is_set("size"));
        parser.parse("size=").unwrap();
        assert!(parser.get("size").is_none());

        parser.parse("size=128M,mergeable=on").unwrap();
        assert_eq!(parser.get("size"), Some("128M".to_owned()));
        assert_eq!(parser.get("mergeable"), Some("on".to_owned()));

        parser
            .parse("size=128M,mergeable=on,topology=[1,2]")
            .unwrap();
        assert_eq!(parser.get("size"), Some("128M".to_owned()));
        assert_eq!(parser.get("mergeable"), Some("on".to_owned()));
        assert_eq!(parser.get("topology"), Some("[1,2]".to_owned()));

        parser
            .parse("size=128M,mergeable=on,topology=[[1,2],[3,4]]")
            .unwrap();
        assert_eq!(parser.get("size"), Some("128M".to_owned()));
        assert_eq!(parser.get("mergeable"), Some("on".to_owned()));
        assert_eq!(parser.get("topology"), Some("[[1,2],[3,4]]".to_owned()));

        parser.parse("topology=[").unwrap_err();
        parser.parse("topology=[[[]]]]").unwrap_err();
        parser.parse("topology=[\"@\"\"b\"@[1,2]]").unwrap();
        assert_eq!(
            parser
                .convert::<TupleList<String, Vec<u8>>>("topology")
                .unwrap()
                .unwrap(),
            TupleList(vec![Tuple("@\"b".to_owned(), vec![1, 2])])
        );

        parser.parse("cmdline=\"console=ttyS0,9600n8\"").unwrap();
        assert_eq!(
            parser.get("cmdline"),
            Some("console=ttyS0,9600n8".to_owned())
        );
        parser.parse("cmdline=\"").unwrap_err();
        parser.parse("cmdline=\"\"\"").unwrap_err();
    }

    #[test]
    fn parse_bytes() {
        assert_eq!(<String as Parseable>::from_str("a=\"b\"").unwrap(), "a=b");
    }

    #[test]
    fn check_dequote() {
        assert_eq!(dequote("a\u{3b2}\"a\"\"\""), "a\u{3b2}a\"");
    }

    #[test]
    fn test_empty_input() {
        let mut parser = OptionParser::new();
        parser.add("foo");
        parser.parse("").unwrap();
        parser.parse("   ").unwrap();
        assert!(!parser.is_set("foo"));
    }

    #[test]
    fn test_parse_subset_ignores_unknown() {
        let mut parser = OptionParser::new();
        parser.add("known");
        parser.parse_subset("known=val,unknown=other").unwrap();
        assert_eq!(parser.get("known"), Some("val".to_owned()));
        assert!(!parser.is_set("unknown"));
    }

    #[test]
    fn test_add_all() {
        let mut parser = OptionParser::new();
        parser.add_all(&["a", "b", "c"]);
        parser.parse("a=1,b=2,c=3").unwrap();
        assert_eq!(parser.get("a"), Some("1".to_owned()));
        assert_eq!(parser.get("b"), Some("2".to_owned()));
        assert_eq!(parser.get("c"), Some("3".to_owned()));
    }

    #[test]
    fn test_add_valueless() {
        let mut parser = OptionParser::new();
        parser.add_valueless("readonly");
        parser.add("path");
        parser.parse("path=/dev/sda,readonly").unwrap();
        assert!(parser.is_set("readonly"));
        assert_eq!(parser.get("readonly"), None);
        assert_eq!(parser.get("path"), Some("/dev/sda".to_owned()));
    }

    #[test]
    fn test_convert_integer() {
        let mut parser = OptionParser::new();
        parser.add("count");
        parser.parse("count=42").unwrap();
        assert_eq!(parser.convert::<u64>("count").unwrap(), Some(42));
        assert_eq!(parser.convert::<u32>("count").unwrap(), Some(42));
    }

    #[test]
    fn test_convert_unset_returns_none() {
        let mut parser = OptionParser::new();
        parser.add("count");
        assert_eq!(parser.convert::<u64>("count").unwrap(), None);
    }

    #[test]
    fn test_convert_invalid_returns_error() {
        let mut parser = OptionParser::new();
        parser.add("count");
        parser.parse("count=notanumber").unwrap();
        parser.convert::<u64>("count").unwrap_err();
    }

    #[test]
    fn test_toggle() {
        for (input, expected) in [
            ("on", true),
            ("off", false),
            ("true", true),
            ("false", false),
            ("ON", true),
            ("OFF", false),
            ("True", true),
            ("False", false),
        ] {
            let mut parser = OptionParser::new();
            parser.add("flag");
            parser.parse(&format!("flag={input}")).unwrap();
            let toggle = parser.convert::<Toggle>("flag").unwrap().unwrap();
            assert_eq!(toggle.0, expected, "Toggle({input}) should be {expected}");
        }
    }

    #[test]
    fn test_toggle_invalid() {
        let mut parser = OptionParser::new();
        parser.add("flag");
        parser.parse("flag=maybe").unwrap();
        assert!(parser.convert::<Toggle>("flag").is_err());
    }

    #[test]
    fn test_byte_sized() {
        let cases = [
            ("1024", 1024u64),
            ("1K", 1024),
            ("2M", 2 * 1024 * 1024),
            ("4G", 4 * 1024 * 1024 * 1024),
            ("0K", 0),
        ];
        for (input, expected) in cases {
            let mut parser = OptionParser::new();
            parser.add("size");
            parser.parse(&format!("size={input}")).unwrap();
            let bs = parser.convert::<ByteSized>("size").unwrap().unwrap();
            assert_eq!(bs.0, expected, "ByteSized({input}) should be {expected}");
        }
    }

    #[test]
    fn test_byte_sized_invalid() {
        assert!("xyzK".parse::<ByteSized>().is_err());
        assert!("".parse::<ByteSized>().is_err());
    }

    #[test]
    fn test_integer_list_single_values() {
        let list = IntegerList::<u64>::from_str("[1,3,5]").unwrap();
        assert_eq!(list.0, vec![1, 3, 5]);
    }

    #[test]
    fn test_integer_list_ranges() {
        let list = IntegerList::<u64>::from_str("[0,2-4,7]").unwrap();
        assert_eq!(list.0, vec![0, 2, 3, 4, 7]);
    }

    #[test]
    fn test_integer_list_invalid_range() {
        assert!(IntegerList::<u64>::from_str("[5-3]").is_err());
        assert!(IntegerList::<u64>::from_str("[5-5]").is_err());
    }

    #[test]
    fn test_integer_list_too_many_dashes() {
        assert!(IntegerList::<u64>::from_str("[1-2-3]").is_err());
    }

    #[test]
    fn test_integer_list_narrow_type() {
        // A narrower element type parses ranges the same way ...
        let list = IntegerList::<u16>::from_str("[1,3-5]").unwrap();
        assert_eq!(list.0, vec![1u16, 3, 4, 5]);

        // ... but rejects values that do not fit, rather than truncating.
        assert!(IntegerList::<u16>::from_str("[65536]").is_err());
        assert!(IntegerList::<u8>::from_str("[256]").is_err());
    }

    #[test]
    fn test_integer_list_display() {
        let list = IntegerList(vec![1u64, 2, 3]);
        assert_eq!(format!("{list}"), "[1,2,3]");

        let empty = IntegerList::<u64>(vec![]);
        assert_eq!(format!("{empty}"), "[]");

        let single = IntegerList(vec![42u64]);
        assert_eq!(format!("{single}"), "[42]");
    }

    #[test]
    fn test_string_list() {
        let list = StringList::from_str("[foo,bar,baz]").unwrap();
        assert_eq!(list.0, vec!["foo", "bar", "baz"]);
    }

    #[test]
    fn test_string_list_no_brackets() {
        let list = StringList::from_str("foo,bar").unwrap();
        assert_eq!(list.0, vec!["foo", "bar"]);
    }

    #[test]
    fn test_tuple_single_pair() {
        let t = Tuple::<String, u64>::from_str("foo@42").unwrap();
        assert_eq!(t, Tuple("foo".to_owned(), 42));
        let t = Tuple::<String, Vec<u64>>::from_str("foo@[42]").unwrap();
        assert_eq!(t, Tuple("foo".to_owned(), vec![42]));
    }

    #[test]
    fn test_tuple_allowed_whitespace() {
        let t = Tuple::<String, u64>::from_str(" foo@42").unwrap();
        assert_eq!(t, Tuple("foo".to_owned(), 42));
        let t = Tuple::<String, u64>::from_str("foo@42 ").unwrap();
        assert_eq!(t, Tuple("foo".to_owned(), 42));
        let t = Tuple::<String, u64>::from_str(" foo@42 ").unwrap();
        assert_eq!(t, Tuple("foo".to_owned(), 42));
        let t = Tuple::<u64, u64>::from_str(" 5@42 ").unwrap();
        assert_eq!(t, Tuple(5, 42));
        // Still a valid string as key, even with trailing whitespace
        let t = Tuple::<String, u64>::from_str(" foo @42 ").unwrap();
        assert_eq!(t, Tuple("foo ".to_owned(), 42));
    }

    #[test]
    fn test_tuple_whitespace_surrounding_delimiter_fails() {
        let e = Tuple::<String, u64>::from_str("foo@ 42").unwrap_err();
        assert!(
            matches!(e, TupleError::InvalidInteger(_)),
            "Expected \"ParseInt\"; got \"{e:?}\"",
        );
        let expected_value = "42 ";
        let e = Tuple::<u64, Vec<u64>>::from_str("42 @[]").unwrap_err();
        assert!(
            matches!(e, TupleError::InvalidValue(ref s) if s == expected_value),
            "Expected \"{:?}\"; got \"{e:?}\"",
            TupleError::InvalidValue(expected_value.to_string()),
        );
        // We abuse of the fact that space can be converted to a valid string as long as the
        // string isn't empty. We use this to check the correct error for tuple value parsing.
        let e = Tuple::<String, u64>::from_str(" foo @ 42 ").unwrap_err();
        assert!(
            matches!(e, TupleError::InvalidInteger(_)),
            "Expected \"ParseInt\"; got \"{e:?}\"",
        );
        // Cannot parse the space into a list
        let expected_value = "";
        let e = Tuple::<u64, Vec<u64>>::from_str("42@ []").unwrap_err();
        assert!(
            matches!(
                e,
                TupleError::InvalidIntegerList(
                    IntegerListParseError::InvalidValue(ref s),
                ) if s == expected_value
            ),
            "Expected \"{:?}\"; got \"{e:?}\"",
            TupleError::InvalidIntegerList(IntegerListParseError::InvalidValue(
                expected_value.to_string()
            ),)
        );
    }

    #[test]
    fn test_tuple_list_single_pair() {
        let t = TupleList::<String, u64>::from_str("[foo@42]").unwrap();
        assert_eq!(t, TupleList(vec![Tuple("foo".to_owned(), 42)]));
    }

    #[test]
    fn test_tuple_list_multiple_pairs() {
        let t = TupleList::<String, Vec<u64>>::from_str("[a@[1,2],b@[3,4]]").unwrap();
        assert_eq!(
            t,
            TupleList(vec![
                Tuple("a".to_owned(), vec![1, 2]),
                Tuple("b".to_owned(), vec![3, 4]),
            ])
        );
    }

    #[test]
    fn test_tuple_list_trim_whitespace() {
        let t = TupleList::<String, Vec<u64>>::from_str("[a@[1,2], b@[3,4] ,\tc@[5,6],\nd@[7,8]]")
            .unwrap();
        assert_eq!(
            t,
            TupleList(vec![
                Tuple("a".to_owned(), vec![1, 2]),
                Tuple("b".to_owned(), vec![3, 4]),
                Tuple("c".to_owned(), vec![5, 6]),
                Tuple("d".to_owned(), vec![7, 8]),
            ])
        );
    }

    #[test]
    fn test_tuple_missing_at_separator() {
        Tuple::<String, u64>::from_str("foo42").unwrap_err();
    }

    #[test]
    fn test_tuple_missing_key() {
        let expected_value = "@42";
        let e = Tuple::<String, u64>::from_str("@42").unwrap_err();
        assert!(
            matches!(e, TupleError::EmptyKey(ref s) if s == expected_value),
            "Expected \"{:?}\"; got \"{e:?}\"",
            TupleError::EmptyKey(expected_value.to_string()),
        );
    }

    #[test]
    fn test_tuple_reject_whitespace_as_empty_key() {
        let expected_value = "@42";
        let e = Tuple::<String, u64>::from_str(" @42").unwrap_err();
        assert!(
            matches!(e, TupleError::EmptyKey(ref s) if s == expected_value),
            "Expected \"{:?}\"; got \"{e:?}\"",
            TupleError::EmptyKey(expected_value.to_string()),
        );
    }

    #[test]
    fn test_split_commas_unbalanced_bracket() {
        split_commas("[a,b").unwrap_err();
        split_commas("a]").unwrap_err();
    }

    #[test]
    fn test_split_commas_unbalanced_quote() {
        split_commas("\"abc").unwrap_err();
    }

    #[test]
    fn test_quoted_value_with_commas() {
        let mut parser = OptionParser::new();
        parser.add("cmd");
        parser.parse("cmd=\"a,b,c\"").unwrap();
        assert_eq!(parser.get("cmd"), Some("a,b,c".to_owned()));
    }

    #[test]
    #[should_panic(expected = "forbidden character")]
    fn test_add_option_with_equals() {
        let mut parser = OptionParser::new();
        parser.add("bad=name");
    }

    #[test]
    #[should_panic(expected = "forbidden character")]
    fn test_add_option_with_comma() {
        let mut parser = OptionParser::new();
        parser.add("bad,name");
    }

    #[test]
    #[should_panic(expected = "forbidden character")]
    fn test_add_option_with_bracket() {
        let mut parser = OptionParser::new();
        parser.add("bad[name");
    }
}
