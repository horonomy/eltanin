//! `eltanin` CLI entrypoint (F-M1-008, HORO-823/845/846;
//! `session` subcommand F-M2-001, HORO-791).
#![forbid(unsafe_code)]

use std::process::ExitCode as ProcessExitCode;

use eltanin_cli::approve::{self, ApproveCliOutcome};
use eltanin_cli::args::{parse, Invocation};
use eltanin_cli::failure::LaunchFailure;
use eltanin_cli::launch::{self, LaunchOutcome};
use eltanin_cli::session::{self, SessionCliOutcome};

fn main() -> ProcessExitCode {
    let argv = std::env::args_os().skip(1);
    let invocation = match parse(argv) {
        Ok(invocation) => invocation,
        Err(error) => return report(&LaunchFailure::from(error)),
    };

    match invocation {
        Invocation::Run(invocation) => match launch::run(&invocation) {
            LaunchOutcome::Failure(failure) => report(&failure),
            LaunchOutcome::Exit(code) => ProcessExitCode::from(code),
        },
        Invocation::Session(invocation) => match session::run(&invocation) {
            SessionCliOutcome::Ok(message) => {
                println!("eltanin: {message}");
                ProcessExitCode::SUCCESS
            }
            SessionCliOutcome::Failure(failure) => report(&failure),
        },
        Invocation::Approve(invocation) => match approve::run(&invocation) {
            ApproveCliOutcome::Ok(message) => {
                println!("eltanin: {message}");
                ProcessExitCode::SUCCESS
            }
            ApproveCliOutcome::Failure(failure) => report(&failure),
        },
    }
}

fn report(failure: &LaunchFailure) -> ProcessExitCode {
    eprintln!("eltanin: {}", failure.message());
    eprintln!("eltanin: {}", failure.next_action());
    ProcessExitCode::from(failure.exit_code().code())
}
