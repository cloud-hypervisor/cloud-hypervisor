#![allow(dead_code)]
#![cfg(not(remain_stable_testing))]
#![feature(proc_macro_hygiene, stmt_expr_attributes)]

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
fn test_match() {
    let value = TestEnum::A;

    #[remain::sorted]
    let _ = match value {
        TestEnum::A => {}
        TestEnum::B => {}
        TestEnum::C => {}
        _ => {}
    };
}

#[test]
fn test_let() {
    let value = TestEnum::A;

    #[remain::sorted]
    match value {
        TestEnum::A => {}
        TestEnum::B => {}
        TestEnum::C => {}
        _ => {}
    }
}
