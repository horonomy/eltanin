//! Bounded, fail-closed single-request connection handling (F-M1-006,
//! HORO-839).
//!
//! [`serve_connection`] is the entire lifecycle of one accepted socket:
//! read exactly one framed request, dispatch it, write exactly one
//! framed response, close. No loop, no retry. See this function's own
//! doc comment for the exact failure-to-response mapping.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Duration;

use eltanin_core::envelope::Versioned;
use eltanin_protocol::framing::{
    decode_frame_len, decode_request, encode_response, peek_request_id, FramingError, ProtocolError,
};
use eltanin_protocol::request::RequestId;
use eltanin_protocol::response::{AgentResponse, ErrorCode, ResponseBody};

use crate::handler::RequestHandler;
use crate::peer::PeerContextSource;

enum ReadOutcome {
    Complete,
    /// Zero bytes were read on the very first attempt — the peer closed
    /// the connection without sending anything. Not an error: a
    /// liveness probe or port-scan-equivalent is not malformed input.
    Eof,
    /// Some bytes were read, then the peer closed or the read timed out
    /// before the rest arrived.
    Partial,
}

fn read_full(stream: &mut UnixStream, buf: &mut [u8]) -> io::Result<ReadOutcome> {
    let mut total = 0;
    while total < buf.len() {
        match stream.read(&mut buf[total..]) {
            Ok(0) => {
                return Ok(if total == 0 {
                    ReadOutcome::Eof
                } else {
                    ReadOutcome::Partial
                });
            }
            Ok(n) => total += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(ReadOutcome::Complete)
}

/// Outcome of reading one complete length-prefixed frame body off the
/// wire, before any JSON decoding is attempted.
enum FrameRead {
    /// The peer closed without sending anything — not an error.
    Eof,
    /// The 4-byte header or the body itself was short, timed out, or
    /// otherwise failed to read in full.
    Failed,
    /// The header named a length exceeding the bound — rejected before
    /// a body buffer of that size was ever allocated.
    Oversized,
    Ok(Vec<u8>),
}

fn read_frame(stream: &mut UnixStream) -> FrameRead {
    let mut header = [0u8; 4];
    match read_full(stream, &mut header) {
        Ok(ReadOutcome::Eof) => return FrameRead::Eof,
        Ok(ReadOutcome::Partial) | Err(_) => return FrameRead::Failed,
        Ok(ReadOutcome::Complete) => {}
    }

    let len = match decode_frame_len(header) {
        Ok(len) => len,
        Err(FramingError::Oversized { .. }) => return FrameRead::Oversized,
    };

    let mut body = vec![0u8; len];
    match read_full(stream, &mut body) {
        Ok(ReadOutcome::Complete) => FrameRead::Ok(body),
        Ok(ReadOutcome::Eof | ReadOutcome::Partial) | Err(_) => FrameRead::Failed,
    }
}

fn send(stream: &mut UnixStream, request_id: Option<RequestId>, body: AgentResponse) {
    let response = Versioned::current(ResponseBody { request_id, body });
    let framed = encode_response(&response).unwrap_or_else(|FramingError::Oversized { .. }| {
        // Every MVP 1.0 response shape is far below MAX_FRAME_BYTES (see
        // framing.rs's own docs); reachable only if that invariant is
        // ever violated, in which case Internal is the honest answer
        // rather than propagating an oversize error for a response the
        // server itself produced.
        let fallback = Versioned::current(ResponseBody {
            request_id,
            body: AgentResponse::Error {
                code: ErrorCode::Internal,
            },
        });
        encode_response(&fallback).expect("a bare Error response is always within bounds")
    });
    let _ = stream.write_all(&framed).and_then(|()| stream.flush());
}

fn fail(stream: &mut UnixStream, request_id: Option<RequestId>, code: ErrorCode) {
    send(stream, request_id, AgentResponse::Error { code });
}

/// Serve exactly one request on `stream`, then let the caller close it.
///
/// Failure mapping (load-bearing, not incidental):
///
/// | Step | Failure | Response |
/// |---|---|---|
/// | timeouts | — | `io_timeout` applied to both read and write, so a stalled client cannot hold a connection thread forever |
/// | peer derivation | fails | `Error { Internal }`, close |
/// | 4-byte length header | EOF at byte 0 | none, clean close |
/// | | partial/timeout | `Error { MalformedRequest }`, id `None` |
/// | length check | oversized | `Error { Oversized }`, id `None` — **closed without reading one body byte** |
/// | body read | short/timeout | `Error { MalformedRequest }`, id `None` |
/// | decode | unsupported version | `Error { UnsupportedVersion { found, expected } }`, id recovered via `peek_request_id` |
/// | | malformed | `Error { MalformedRequest }`, id recovered via `peek_request_id` |
/// | | oversized (defense in depth; unreachable in practice — the length check above already bounds `body`) | `Error { Oversized }`, id recovered via `peek_request_id` |
/// | handler | panics | `Error { Internal }`, id echoed — thread isolation is the primary containment; this converts what would otherwise be a silent connection drop into a real answer |
pub fn serve_connection(
    mut stream: UnixStream,
    io_timeout: Duration,
    handler: &dyn RequestHandler,
    peer_source: &dyn PeerContextSource,
) {
    if stream.set_read_timeout(Some(io_timeout)).is_err()
        || stream.set_write_timeout(Some(io_timeout)).is_err()
    {
        return;
    }

    let Ok(peer) = peer_source.derive(&stream) else {
        return fail(&mut stream, None, ErrorCode::Internal);
    };

    let body = match read_frame(&mut stream) {
        FrameRead::Eof => return,
        FrameRead::Failed => return fail(&mut stream, None, ErrorCode::MalformedRequest),
        FrameRead::Oversized => return fail(&mut stream, None, ErrorCode::Oversized),
        FrameRead::Ok(body) => body,
    };

    let request = match decode_request(&body) {
        Ok(request) => request,
        Err(ProtocolError::Version(v)) => {
            let code = ErrorCode::UnsupportedVersion {
                found: v.found,
                expected: v.expected,
            };
            return fail(&mut stream, peek_request_id(&body), code);
        }
        Err(ProtocolError::Malformed) => {
            return fail(
                &mut stream,
                peek_request_id(&body),
                ErrorCode::MalformedRequest,
            )
        }
        Err(ProtocolError::Framing(FramingError::Oversized { .. })) => {
            return fail(&mut stream, peek_request_id(&body), ErrorCode::Oversized)
        }
    };

    let request_id = request.payload.request_id;
    let response = catch_unwind(AssertUnwindSafe(|| {
        handler.handle(&request.payload.body, &peer)
    }))
    .unwrap_or(AgentResponse::Error {
        code: ErrorCode::Internal,
    });

    send(&mut stream, Some(request_id), response);
}
