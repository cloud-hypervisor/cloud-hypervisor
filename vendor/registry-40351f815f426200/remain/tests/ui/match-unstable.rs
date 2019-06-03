#![feature(proc_macro_hygiene, stmt_expr_attributes)]

use remain::sorted;

enum E {
    Aaa,
    Bbb(u8, u8),
    Ccc(u8),
    Ddd { u: u8 },
}

fn main() {
    let value = E::Aaa;

    #[sorted]
    match value {
        E::Aaa => {}
        E::Ccc(_) => {}
        E::Ddd { u: _ } => {}
        E::Bbb(_, _) => {}
    }
}
