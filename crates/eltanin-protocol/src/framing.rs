//! Frame bounds and checked encode/decode.
//!
//! Wire format: a 4-byte big-endian `u32` length prefix, followed by
//! that many bytes of UTF-8 JSON. This module owns the bound and the
//! checked parse; it does not own a socket.
//!
//! **Named obligation on HORO-839** (the transport/runtime ticket,
//! following the same pattern as `lease.rs`'s "contract on F-M1-006"
//! note): the transport must call [`decode_frame_len`] on the 4-byte
//! header and reject before allocating a read buffer for the body. A
//! size check applied only after reading the full body still permits an
//! unbounded allocation driven entirely by an attacker-chosen length
//! prefix. This crate provides the constant and the checked parse; it
//! cannot enforce that the call site actually uses them before reading.

use eltanin_core::envelope::{UnsupportedVersion, DOMAIN_SCHEMA_VERSION};
use serde::Deserialize;

use crate::request::{Request, RequestId};
use crate::response::Response;

/// Maximum accepted frame body size, in bytes. The largest legitimate
/// MVP 1.0 request is a `RequestLease` carrying opaque
/// [`eltanin_core::resource::ResourceIdentity`] strings — three orders
/// of magnitude below this bound. JSON nesting depth is separately
/// bounded by `serde_json`'s own recursion limit; this crate does not
/// reimplement that check.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

/// Why a frame could not be encoded or its length header accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FramingError {
    #[error("frame length {len} exceeds the maximum {max}")]
    Oversized { len: usize, max: usize },
}

/// Why a decoded wire request could not be turned into a [`Request`].
/// Deliberately carries no parser detail — see `response.rs`'s
/// [`crate::response::ErrorCode`] docs for why.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProtocolError {
    #[error(transparent)]
    Framing(#[from] FramingError),
    #[error("request body is malformed or unrecognized")]
    Malformed,
    #[error(transparent)]
    Version(#[from] UnsupportedVersion),
}

/// Decode a 4-byte big-endian length header, rejecting it before any
/// buffer for the body is allocated. See the module docs' named
/// obligation on the transport.
///
/// # Errors
///
/// Returns [`FramingError::Oversized`] if the encoded length exceeds
/// [`MAX_FRAME_BYTES`].
pub fn decode_frame_len(header: [u8; 4]) -> Result<usize, FramingError> {
    let len = u32::from_be_bytes(header) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(FramingError::Oversized {
            len,
            max: MAX_FRAME_BYTES,
        });
    }
    Ok(len)
}

/// Prepend a 4-byte big-endian length header to `payload`.
///
/// # Errors
///
/// Returns [`FramingError::Oversized`] if `payload` exceeds
/// [`MAX_FRAME_BYTES`].
///
/// # Panics
///
/// Never in practice: the length-to-`u32` conversion can only fail for a
/// `payload` longer than [`u32::MAX`] bytes, which the oversize check
/// above already rejects since [`MAX_FRAME_BYTES`] is far smaller.
pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, FramingError> {
    if payload.len() > MAX_FRAME_BYTES {
        return Err(FramingError::Oversized {
            len: payload.len(),
            max: MAX_FRAME_BYTES,
        });
    }
    let len = u32::try_from(payload.len()).expect("checked above against MAX_FRAME_BYTES");
    let mut framed = Vec::with_capacity(4 + payload.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(payload);
    Ok(framed)
}

/// Peeks only the envelope `version` field, ignoring the shape of
/// `payload` entirely — usable even when the payload body is malformed,
/// so a version mismatch can be reported correctly instead of masked by
/// an unrelated payload-shape error.
#[derive(Deserialize)]
struct VersionPeek {
    version: u16,
}

#[derive(Deserialize)]
struct HeaderPeek {
    payload: HeaderPayloadPeek,
}

#[derive(Deserialize)]
struct HeaderPayloadPeek {
    request_id: RequestId,
}

/// Best-effort peek at a frame's envelope version, without requiring the
/// rest of the payload to parse. Returns `None` if even that much
/// cannot be recovered (e.g. the frame is not a JSON object at all).
#[must_use]
pub fn peek_version(body: &[u8]) -> Option<u16> {
    serde_json::from_slice::<VersionPeek>(body)
        .ok()
        .map(|p| p.version)
}

/// Best-effort peek at a frame's [`RequestId`], for correlating an error
/// response to a request whose body could not be fully decoded. Returns
/// `None` when the id itself cannot be recovered (e.g. `payload` is not
/// even a JSON object) — callers must not fabricate an id in that case.
#[must_use]
pub fn peek_request_id(body: &[u8]) -> Option<RequestId> {
    serde_json::from_slice::<HeaderPeek>(body)
        .ok()
        .map(|p| p.payload.request_id)
}

/// Decode one complete frame body (length prefix already stripped by the
/// transport) into a [`Request`].
///
/// Checks version before attempting a full-shape decode: a frame with an
/// unsupported version and a malformed payload is reported as
/// [`ProtocolError::Version`], not [`ProtocolError::Malformed`] — a
/// client on an old/new build should learn *why* it was rejected even
/// when it could never have produced a valid payload for this build's
/// schema anyway.
///
/// # Errors
///
/// Returns [`ProtocolError::Framing`] if `body` exceeds
/// [`MAX_FRAME_BYTES`] (defense in depth — the transport should already
/// have rejected this via [`decode_frame_len`]);
/// [`ProtocolError::Version`] if the envelope names an unsupported
/// schema version; [`ProtocolError::Malformed`] for every other decode
/// failure (unknown operation, unknown field, non-object payload,
/// trailing bytes, truncated frame).
pub fn decode_request(body: &[u8]) -> Result<Request, ProtocolError> {
    if body.len() > MAX_FRAME_BYTES {
        return Err(FramingError::Oversized {
            len: body.len(),
            max: MAX_FRAME_BYTES,
        }
        .into());
    }
    let version = peek_version(body).ok_or(ProtocolError::Malformed)?;
    if version != DOMAIN_SCHEMA_VERSION {
        return Err(UnsupportedVersion {
            found: version,
            expected: DOMAIN_SCHEMA_VERSION,
        }
        .into());
    }
    serde_json::from_slice::<Request>(body).map_err(|_| ProtocolError::Malformed)
}

/// Encode a [`Response`] as one length-prefixed frame.
///
/// # Errors
///
/// Returns [`FramingError::Oversized`] if the serialized response
/// exceeds [`MAX_FRAME_BYTES`] — this should not happen for any MVP 1.0
/// response shape, but is checked rather than assumed.
///
/// # Panics
///
/// Never in practice: every field type in [`Response`] implements
/// `Serialize` without a fallible path (no floats, no non-string map
/// keys), so `serde_json::to_vec` cannot fail for this type.
pub fn encode_response(response: &Response) -> Result<Vec<u8>, FramingError> {
    let payload = serde_json::to_vec(response).expect("Response serialization cannot fail");
    encode_frame(&payload)
}

/// Encode a [`Request`] as one length-prefixed frame — the client-side
/// mirror of [`encode_response`], for a caller (`eltanin-cli`) that
/// speaks the client direction of this same protocol.
///
/// # Errors
///
/// Returns [`FramingError::Oversized`] if the serialized request exceeds
/// [`MAX_FRAME_BYTES`].
///
/// # Panics
///
/// Never in practice: every field type in [`Request`] implements
/// `Serialize` without a fallible path, mirroring [`encode_response`]'s
/// own guarantee.
pub fn encode_request(request: &Request) -> Result<Vec<u8>, FramingError> {
    let payload = serde_json::to_vec(request).expect("Request serialization cannot fail");
    encode_frame(&payload)
}

/// Decode one complete frame body into a [`Response`] — the client-side
/// mirror of [`decode_request`], for a caller (`eltanin-cli`) reading an
/// agent's reply. Applies the same version-peek-before-shape-decode
/// ordering: a response with an unsupported version and an otherwise
/// unparseable payload is reported as [`ProtocolError::Version`], not
/// [`ProtocolError::Malformed`].
///
/// # Errors
///
/// Returns [`ProtocolError::Framing`] if `body` exceeds
/// [`MAX_FRAME_BYTES`]; [`ProtocolError::Version`] if the envelope names
/// an unsupported schema version; [`ProtocolError::Malformed`] for every
/// other decode failure.
pub fn decode_response(body: &[u8]) -> Result<Response, ProtocolError> {
    if body.len() > MAX_FRAME_BYTES {
        return Err(FramingError::Oversized {
            len: body.len(),
            max: MAX_FRAME_BYTES,
        }
        .into());
    }
    let version = peek_version(body).ok_or(ProtocolError::Malformed)?;
    if version != DOMAIN_SCHEMA_VERSION {
        return Err(UnsupportedVersion {
            found: version,
            expected: DOMAIN_SCHEMA_VERSION,
        }
        .into());
    }
    serde_json::from_slice::<Response>(body).map_err(|_| ProtocolError::Malformed)
}
