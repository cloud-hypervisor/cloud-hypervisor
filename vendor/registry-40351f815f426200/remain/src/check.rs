use syn::{Arm, Ident, Result, Variant};
use syn::{Error, Field, Pat, PatIdent};

use crate::compare::Path;
use crate::format;
use crate::parse::Input::{self, *};

pub fn sorted(input: Input) -> Result<()> {
    let paths = match input {
        Enum(item) => collect_paths(item.variants)?,
        Struct(fields) => collect_paths(fields.named)?,
        Match(expr) | Let(expr) => collect_paths(expr.arms)?,
    };

    for i in 1..paths.len() {
        let cur = &paths[i];
        if *cur < paths[i - 1] {
            let lesser = cur;
            let correct_pos = paths[..i - 1].binary_search(cur).unwrap_err();
            let greater = &paths[correct_pos];
            return Err(format::error(lesser, greater));
        }
    }

    Ok(())
}

fn collect_paths<I>(iter: I) -> Result<Vec<Path>>
where
    I: IntoIterator,
    I::Item: IntoPath,
{
    iter.into_iter().map(IntoPath::into_path).collect()
}

trait IntoPath {
    fn into_path(self) -> Result<Path>;
}

impl IntoPath for Variant {
    fn into_path(self) -> Result<Path> {
        Ok(Path {
            segments: vec![self.ident],
        })
    }
}

impl IntoPath for Field {
    fn into_path(self) -> Result<Path> {
        Ok(Path {
            segments: vec![self.ident.expect("must be named field")],
        })
    }
}

impl IntoPath for Arm {
    fn into_path(self) -> Result<Path> {
        // Sort by just the first pat.
        let pat = self.pats.into_iter().next().expect("at least one pat");

        let segments = match pat {
            Pat::Wild(pat) => vec![Ident::from(pat.underscore_token)],
            Pat::Path(pat) => idents_of_path(pat.path),
            Pat::Struct(pat) => idents_of_path(pat.path),
            Pat::TupleStruct(pat) => idents_of_path(pat.path),
            Pat::Ident(ref pat) if is_just_ident(pat) => vec![pat.ident.clone()],
            other => {
                let msg = "unsupported by #[remain::sorted]";
                return Err(Error::new_spanned(other, msg));
            }
        };

        Ok(Path { segments })
    }
}

fn idents_of_path(path: syn::Path) -> Vec<Ident> {
    path.segments.into_iter().map(|seg| seg.ident).collect()
}

fn is_just_ident(pat: &PatIdent) -> bool {
    pat.by_ref.is_none() && pat.mutability.is_none() && pat.subpat.is_none()
}
