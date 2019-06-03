#![allow(dead_code)]

#[remain::sorted]
pub enum TestEnum {
    A,
    B,
    C,
    D,
}

#[remain::sorted]
pub struct TestStruct {
    a: usize,
    b: usize,
    c: usize,
    d: usize,
}

#[test]
#[remain::check]
fn test_match() {
    let value = TestEnum::A;

    #[sorted]
    let _ = match value {
        TestEnum::A => {}
        TestEnum::B => {}
        TestEnum::C => {}
        _ => {}
    };
}

#[test]
#[remain::check]
fn test_let() {
    let value = TestEnum::A;

    #[sorted]
    match value {
        TestEnum::A => {}
        TestEnum::B => {}
        TestEnum::C => {}
        _ => {}
    }
}
