#[remain::check]
fn main() {
    let value = 0;

    #[sorted]
    match value {
        0..=20 => {}
        _ => {}
    }
}
