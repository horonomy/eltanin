//! `eltanin` CLI entrypoint (F-M1-008, HORO-823/845/846).
//!
//! Only `run` exists so far.
#![forbid(unsafe_code)]

use std::process::ExitCode as ProcessExitCode;

use eltanin_cli::args::parse_run;
use eltanin_cli::failure::LaunchFailure;
use eltanin_cli::launch::{self, LaunchOutcome};

fn main() -> ProcessExitCode {
    let argv = std::env::args_os().skip(1);
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
