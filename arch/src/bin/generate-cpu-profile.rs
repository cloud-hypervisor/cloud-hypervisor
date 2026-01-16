#![cfg(all(
    target_arch = "x86_64",
    feature = "cpu_profile_generation",
    feature = "kvm"
))]
use std::io::BufWriter;

use anyhow::Context;
use clap::{Arg, Command};

fn main() -> anyhow::Result<()> {
    let cmd_arg = Command::new("generate-cpu-profile")
        .version(env!("CARGO_PKG_VERSION"))
        .arg_required_else_help(true)
        .arg(
            Arg::new("name")
                .help("The name to give the CPU profile")
                .num_args(1)
                .required(true),
        )
        .get_matches();

    let profile_name = cmd_arg.get_one::<String>("name").unwrap();

    let hypervisor = hypervisor::new().context("Could not obtain hypervisor")?;
    // TODO: Consider letting the user provide a file path as a target instead of writing to stdout.
    // The way it is now should be sufficient for a PoC however.
    let writer = BufWriter::new(std::io::stdout().lock());
    arch::x86_64::cpu_profile_generation::generate_profile_data(
        writer,
        hypervisor.as_ref(),
        profile_name,
    )
}
