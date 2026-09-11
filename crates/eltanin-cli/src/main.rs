//! `eltanin` CLI entrypoint (F-M1-008, HORO-823/845).
//!
//! Only `run` exists so far. This binary honors the argv/exit-code
//! contract HORO-845 defines (`docs/product/CLI_CONTRACT.md`); the
//! actual agent-connection/spawn/supervise launch path is HORO-846's.
#![forbid(unsafe_code)]

use std::path::Path;
use std::process::ExitCode as ProcessExitCode;

use eltanin_cli::args::parse_run;
use eltanin_cli::failure::LaunchFailure;

fn main() -> ProcessExitCode {
    let argv = std::env::args_os().skip(1);
    match parse_run(argv) {
        Ok(invocation) => {
            eprintln!(
                "eltanin run: parsed profile {:?}, program {:?} — launch not yet implemented \
                 (HORO-846)",
                invocation.profile.as_str(),
                Path::new(&invocation.program).display()
            );
            ProcessExitCode::from(
                LaunchFailure::AgentUnavailable(
                    "eltanin run's launch path is not yet implemented (HORO-846)".to_string(),
                )
                .exit_code()
                .code(),
            )
        }
        Err(error) => {
            let failure = LaunchFailure::from(error);
            eprintln!("eltanin: {}", failure.message());
            eprintln!("eltanin: {}", failure.next_action());
            ProcessExitCode::from(failure.exit_code().code())
        }
    }
}
