use proc_macro2::TokenStream;
use quote::TokenStreamExt;
use std::fmt::{self, Display};
use syn::Error;

use crate::compare::Path;

impl Display for Path {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        for (i, segment) in self.segments.iter().enumerate() {
            if i > 0 {
                formatter.write_str("::")?;
            }
            segment.fmt(formatter)?;
        }
        Ok(())
    }
}

pub fn error(lesser: &Path, greater: &Path) -> Error {
    let mut spans = TokenStream::new();
    spans.append_all(&lesser.segments);

    let msg = format!("{} should sort before {}", lesser, greater);

    Error::new_spanned(spans, msg)
}
