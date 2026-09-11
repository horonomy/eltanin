//! `eltanin-explain` — minimal standalone inspection binary (F-M1-009,
//! HORO-824), ahead of the real `eltanin` CLI (F-M1-008, HORO-823, not
//! yet started) — the same role `eltanin-agentd` played ahead of the
//! real CLI in HORO-840. The eventual `eltanin explain` subcommand calls
//! `eltanin_audit::explain` directly; nothing here blocks on the CLI.
#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use eltanin_audit::explain::{read_log, select, SelectionResult, Selector};
use eltanin_core::lease::{IssuerInstanceId, LeaseId};

fn parse_event_id(text: &str) -> Result<eltanin_audit::record::AuditEventId, String> {
    let (instance, sequence) = text
        .rsplit_once('#')
        .ok_or_else(|| format!("expected <instance>#<sequence>, got {text:?}"))?;
    let sequence: u64 = sequence
        .parse()
        .map_err(|e| format!("invalid sequence in {text:?}: {e}"))?;
    Ok(eltanin_audit::record::AuditEventId {
        instance: IssuerInstanceId::new(instance),
        sequence,
    })
}

fn run() -> Result<bool, String> {
    let mut log_path = env::var("ELTANIN_AUDIT_LOG").ok().map(PathBuf::from);
    let mut selector: Option<Selector> = None;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--log" => {
                let value = args.next().ok_or("--log requires a value")?;
                log_path = Some(PathBuf::from(value));
            }
            "--event" => {
                let value = args.next().ok_or("--event requires a value")?;
                selector = Some(Selector::Event(parse_event_id(&value)?));
            }
            "--lease" => {
                let value = args.next().ok_or("--lease requires a value")?;
                let event_id = parse_event_id(&value)?;
                selector = Some(Selector::Lease(LeaseId {
                    issuer: event_id.instance,
                    sequence: event_id.sequence,
                }));
            }
            "--pid" => {
                let value = args.next().ok_or("--pid requires a value")?;
                let pid: u32 = value.parse().map_err(|e| format!("invalid pid: {e}"))?;
                selector = Some(Selector::Pid(pid));
            }
            other => return Err(format!("unrecognized argument: {other}")),
        }
    }

    let log_path = log_path.ok_or("no audit log path given (--log or ELTANIN_AUDIT_LOG)")?;
    let selector = selector.ok_or("one of --event, --lease, --pid is required")?;

    let scan = read_log(&log_path).map_err(|e| e.to_string())?;
    match select(&scan, &selector) {
        SelectionResult::Found(records) => {
            for record in records {
                println!("{}", eltanin_audit::explain::render(record));
            }
            Ok(true)
        }
        SelectionResult::PossiblyLost => {
            println!(
                "no record found for that event id, but it falls inside an observed sequence \
                 gap for its agent instance — it may exist and have failed to persist (audit \
                 persistence is best-effort; see docs/product/SECURITY_MODEL.md)."
            );
            Ok(false)
        }
        SelectionResult::NotFound => {
            println!("no matching record found.");
            Ok(false)
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(2),
        Err(message) => {
            eprintln!("eltanin-explain: {message}");
            ExitCode::FAILURE
        }
    }
}
