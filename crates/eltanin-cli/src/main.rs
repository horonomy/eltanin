//! `eltanin` CLI entrypoint (F-M1-008, HORO-823/845/846).
//!
//! Only `run` exists so far.
#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::process::ExitCode as ProcessExitCode;

use eltanin_cli::args::parse_run;
use eltanin_cli::failure::LaunchFailure;
use eltanin_cli::launch::{self, LaunchOutcome};

const USAGE: &str = "\
Usage: eltanin run --profile <name> -- <program> [args...]

Controlled, auditable launch of a workload under an authorization profile.

Options:
  -h, --help     Print this help and exit
  -V, --version  Print version and exit

See docs/product/CLI_CONTRACT.md for the full argv grammar.";

fn main() -> ProcessExitCode {
    let argv: Vec<_> = std::env::args_os().skip(1).collect();

    if let Some(first) = argv.first() {
        if first == OsStr::new("--help") || first == OsStr::new("-h") {
            println!("eltanin {}\n\n{USAGE}", env!("CARGO_PKG_VERSION"));
            return ProcessExitCode::SUCCESS;
        }
        if first == OsStr::new("--version") || first == OsStr::new("-V") {
            println!("eltanin {}", env!("CARGO_PKG_VERSION"));
            return ProcessExitCode::SUCCESS;
        }
    }

    let invocation = match parse_run(argv) {
        Ok(invocation) => invocation,
        Err(error) => return report(&LaunchFailure::from(error)),
    };

    match launch::run(&invocation) {
        LaunchOutcome::Failure(failure) => report(&failure),
        LaunchOutcome::Exit(code) => ProcessExitCode::from(code),
    }
}

fn report(failure: &LaunchFailure) -> ProcessExitCode {
    eprintln!("eltanin: {}", failure.message());
    eprintln!("eltanin: {}", failure.next_action());
    ProcessExitCode::from(failure.exit_code().code())
}
