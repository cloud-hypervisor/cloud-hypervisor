enum E {
    Aaa,
    Bbb(u8, u8),
    Ccc(u8),
    Ddd { u: u8 },
}

#[remain::check]
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
