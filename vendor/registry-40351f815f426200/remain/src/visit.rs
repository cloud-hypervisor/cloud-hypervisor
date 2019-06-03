use quote::quote;
use syn::visit_mut::{self, VisitMut};
use syn::{parse_quote, Attribute, Expr, ExprMatch, ItemFn, Local};

use crate::parse::Input;

pub fn check(input: &mut ItemFn) {
    Checker.visit_item_fn_mut(input);
}

struct Checker;

impl VisitMut for Checker {
    fn visit_expr_mut(&mut self, expr: &mut Expr) {
        visit_mut::visit_expr_mut(self, expr);

        let expr_match = match expr {
            Expr::Match(expr) => expr,
            _ => return,
        };

        if !take_sorted_attr(&mut expr_match.attrs) {
            return;
        }

        let input = expr_match.clone();
        check_and_insert_error(input, expr);
    }

    fn visit_local_mut(&mut self, local: &mut Local) {
        visit_mut::visit_local_mut(self, local);

        let init = match &local.init {
            Some((_, init)) => init,
            None => return,
        };

        let expr_match = match init.as_ref() {
            Expr::Match(expr) => expr,
            _ => return,
        };

        if !take_sorted_attr(&mut local.attrs) {
            return;
        }

        let input = expr_match.clone();
        let expr = local.init.as_mut().unwrap().1.as_mut();
        check_and_insert_error(input, expr);
    }
}

fn take_sorted_attr(attrs: &mut Vec<Attribute>) -> bool {
    for i in 0..attrs.len() {
        let path = &attrs[i].path;
        let path = quote!(#path).to_string();
        if path == "sorted" || path == "remain :: sorted" {
            attrs.remove(i);
            return true;
        }
    }

    false
}

fn check_and_insert_error(input: ExprMatch, out: &mut Expr) {
    let original = quote!(#input);
    let input = Input::Match(input);

    if let Err(err) = crate::check::sorted(input) {
        let err = err.to_compile_error();
        *out = parse_quote!({
            #err
            #original
        });
    }
}
