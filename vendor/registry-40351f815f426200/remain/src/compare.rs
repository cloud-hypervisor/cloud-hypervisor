use proc_macro2::Ident;
use std::cmp::Ordering;

#[derive(PartialEq, Eq)]
pub struct Path {
    pub segments: Vec<Ident>,
}

impl PartialOrd for Path {
    fn partial_cmp(&self, other: &Path) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Path {
    fn cmp(&self, other: &Path) -> Ordering {
        // Lexicographic ordering across path segments.
        for (lhs, rhs) in self.segments.iter().zip(&other.segments) {
            match cmp(&lhs.to_string(), &rhs.to_string()) {
                Ordering::Equal => {}
                non_eq => return non_eq,
            }
        }

        self.segments.len().cmp(&other.segments.len())
    }
}

// TODO: more intelligent comparison
// for example to handle numeric cases like E9 < E10.
fn cmp(lhs: &str, rhs: &str) -> Ordering {
    // Sort `_` last.
    match (lhs == "_", rhs == "_") {
        (true, true) => return Ordering::Equal,
        (true, false) => return Ordering::Greater,
        (false, true) => return Ordering::Less,
        (false, false) => {}
    }

    let lhs = lhs.to_ascii_lowercase();
    let rhs = rhs.to_ascii_lowercase();

    // For now: asciibetical ordering.
    lhs.cmp(&rhs)
}
