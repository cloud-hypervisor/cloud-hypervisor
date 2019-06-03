use proc_macro2::Span;
use syn::parse::{Parse, ParseStream};
use syn::{Attribute, Error, Expr, Fields, Result, Stmt, Token, Visibility};

use crate::emit::Kind;

pub struct Nothing;

impl Parse for Nothing {
    fn parse(_input: ParseStream) -> Result<Self> {
        Ok(Nothing)
    }
}

pub enum Input {
    Enum(syn::ItemEnum),
    Match(syn::ExprMatch),
    Struct(syn::FieldsNamed),
    Let(syn::ExprMatch),
}

impl Input {
    pub fn kind(&self) -> Kind {
        match self {
            Input::Enum(_) => Kind::Enum,
            Input::Match(_) => Kind::Match,
            Input::Struct(_) => Kind::Struct,
            Input::Let(_) => Kind::Let,
        }
    }
}

impl Parse for Input {
    fn parse(input: ParseStream) -> Result<Self> {
        let _ = input.call(Attribute::parse_outer)?;

        if input.peek(Token![match]) {
            let expr = match input.parse()? {
                Expr::Match(expr) => expr,
                _ => unreachable!("expected match"),
            };
            return Ok(Input::Match(expr));
        }

        if input.peek(Token![let]) {
            let stmt = match input.parse()? {
                Stmt::Local(stmt) => stmt,
                _ => unreachable!("expected let"),
            };
            let init = match stmt.init {
                Some((_, init)) => *init,
                None => return Err(unexpected()),
            };
            let expr = match init {
                Expr::Match(expr) => expr,
                _ => return Err(unexpected()),
            };
            return Ok(Input::Let(expr));
        }

        let ahead = input.fork();
        let _: Visibility = ahead.parse()?;
        if ahead.peek(Token![enum]) {
            return input.parse().map(Input::Enum);
        } else if ahead.peek(Token![struct]) {
            let input: syn::ItemStruct = input.parse()?;
            if let Fields::Named(fields) = input.fields {
                return Ok(Input::Struct(fields));
            }
        }

        Err(unexpected())
    }
}

fn unexpected() -> Error {
    let span = Span::call_site();
    let msg = "expected enum, struct, or match expression";
    Error::new(span, msg)
}
