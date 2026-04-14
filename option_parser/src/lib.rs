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
use std::fmt::{Display, Write};
use std::num::ParseIntError;
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
    #[error("unknown option: {0}")]
    UnknownOption(String),
    /// The input string has invalid syntax (unbalanced quotes/brackets, missing `=`).
    #[error("invalid syntax: {0}")]
    InvalidSyntax(String),
    /// A value could not be converted to the requested type.
    #[error("unable to convert {1} for {0}")]
    Conversion(String /* field */, String /* value */),
    /// A value was syntactically valid but semantically wrong.
    #[error("invalid value: {0}")]
    InvalidValue(String),
}
type OptionParserResult<T> = std::result::Result<T, OptionParserError>;

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
    /// [`Tuple`], or [`StringList`].
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
    #[error("invalid value: {0}")]
    InvalidValue(String),
}

impl Parseable for Toggle {
    type Err = ToggleParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
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
    #[error("invalid value: {0}")]
    InvalidValue(String),
}

impl FromStr for ByteSized {
    type Err = ByteSizedParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
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
pub struct IntegerList(pub Vec<u64>);

impl Display for IntegerList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
    #[error("invalid value: {0}")]
    InvalidValue(String),
}

impl Parseable for IntegerList {
    type Err = IntegerListParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
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

            integer_list.push(start_range);

            if items.len() == 2 {
                let end_range = items[1]
                    .parse::<u64>()
                    .map_err(|_| IntegerListParseError::InvalidValue(items[1].to_owned()))?;
                if start_range >= end_range {
                    return Err(IntegerListParseError::InvalidValue((*range).to_string()));
                }

                for i in start_range..end_range {
                    integer_list.push(i + 1);
                }
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
        Ok(IntegerList::from_str(input)
            .map_err(TupleError::InvalidIntegerList)?
            .0
            .iter()
            .map(|v| *v as u8)
            .collect())
    }
}

impl TupleValue for Vec<u64> {
    fn parse_value(input: &str) -> Result<Self, TupleError> {
        Ok(IntegerList::from_str(input)
            .map_err(TupleError::InvalidIntegerList)?
            .0)
    }
}

impl TupleValue for Vec<usize> {
    fn parse_value(input: &str) -> Result<Self, TupleError> {
        Ok(IntegerList::from_str(input)
            .map_err(TupleError::InvalidIntegerList)?
            .0
            .iter()
            .map(|v| *v as usize)
            .collect())
    }
}

/// A list of `key@value` pairs parsed from a bracket-enclosed string.
///
/// The format is `[key1@value1,key2@value2,...]` where `@` separates each
/// pair's elements. `S` is the key type and `T` is the value type.
#[derive(PartialEq, Eq, Debug)]
pub struct Tuple<S, T>(pub Vec<(S, T)>);

#[derive(Error, Debug)]
pub enum TupleError {
    #[error("invalid value: {0}")]
    InvalidValue(String),
    #[error("split outside brackets")]
    SplitOutsideBrackets(#[source] OptionParserError),
    #[error("invalid integer list")]
    InvalidIntegerList(#[source] IntegerListParseError),
    #[error("invalid integer")]
    InvalidInteger(#[source] ParseIntError),
}

impl<S: Parseable, T: TupleValue> Parseable for Tuple<S, T> {
    type Err = TupleError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut list: Vec<(S, T)> = Vec::new();
        let body = s
            .trim()
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .ok_or_else(|| TupleError::InvalidValue(s.to_string()))?;
        let tuples_list = split_commas(body).map_err(TupleError::SplitOutsideBrackets)?;
        for tuple in tuples_list.iter() {
            let mut in_quotes = false;
            let mut last_idx = 0;
            let mut first_val = None;
            for (idx, c) in tuple.as_bytes().iter().enumerate() {
                match c {
                    b'"' => in_quotes = !in_quotes,
                    b'@' if !in_quotes => {
                        if last_idx != 0 {
                            return Err(TupleError::InvalidValue((*tuple).to_string()));
                        }
                        first_val = Some(&tuple[last_idx..idx]);
                        last_idx = idx + 1;
                    }
                    _ => {}
                }
            }
            let item1 = <S as Parseable>::from_str(
                first_val.ok_or(TupleError::InvalidValue((*tuple).to_string()))?,
            )
            .map_err(|_| TupleError::InvalidValue(first_val.unwrap().to_owned()))?;
            let item2 = TupleValue::parse_value(&tuple[last_idx..])?;
            list.push((item1, item2));
        }

        Ok(Tuple(list))
    }
}

/// A list of strings parsed from a bracket-enclosed, comma-separated string.
///
/// The format is `[str1,str2,...]`. Brackets are optional.
#[derive(Default)]
pub struct StringList(pub Vec<String>);

#[derive(Error, Debug)]
pub enum StringListParseError {
    #[error("invalid value: {0}")]
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
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        dequote(s).parse()
    }
}

impl Parseable for StringList {
    type Err = StringListParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
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
        parser
            .parse("size=128M,too_many_equals=foo=bar")
            .unwrap_err();
        parser.parse("size=128M,file=/dev/shm").unwrap_err();

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
                .convert::<Tuple<String, Vec<u8>>>("topology")
                .unwrap()
                .unwrap(),
            Tuple(vec![("@\"b".to_owned(), vec![1, 2])])
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
        let list = IntegerList::from_str("[1,3,5]").unwrap();
        assert_eq!(list.0, vec![1, 3, 5]);
    }

    #[test]
    fn test_integer_list_ranges() {
        let list = IntegerList::from_str("[0,2-4,7]").unwrap();
        assert_eq!(list.0, vec![0, 2, 3, 4, 7]);
    }

    #[test]
    fn test_integer_list_invalid_range() {
        assert!(IntegerList::from_str("[5-3]").is_err());
        assert!(IntegerList::from_str("[5-5]").is_err());
    }

    #[test]
    fn test_integer_list_too_many_dashes() {
        assert!(IntegerList::from_str("[1-2-3]").is_err());
    }

    #[test]
    fn test_integer_list_display() {
        let list = IntegerList(vec![1, 2, 3]);
        assert_eq!(format!("{list}"), "[1,2,3]");

        let empty = IntegerList(vec![]);
        assert_eq!(format!("{empty}"), "[]");

        let single = IntegerList(vec![42]);
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
        let t = Tuple::<String, u64>::from_str("[foo@42]").unwrap();
        assert_eq!(t, Tuple(vec![("foo".to_owned(), 42)]));
    }

    #[test]
    fn test_tuple_multiple_pairs() {
        let t = Tuple::<String, Vec<u64>>::from_str("[a@[1,2],b@[3,4]]").unwrap();
        assert_eq!(
            t,
            Tuple(vec![
                ("a".to_owned(), vec![1, 2]),
                ("b".to_owned(), vec![3, 4]),
            ])
        );
    }

    #[test]
    fn test_tuple_missing_at_separator() {
        Tuple::<String, u64>::from_str("[foo42]").unwrap_err();
    }

    #[test]
    fn test_tuple_missing_brackets() {
        Tuple::<String, u64>::from_str("foo@42").unwrap_err();
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
