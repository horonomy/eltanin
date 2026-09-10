//! Provenance: links an observed [`ExecutionContext`] (F-M1-003) to the
//! [`ComputeRequest`] (F-M1-001) it accompanied, for audit reconstruction
//! (F-M1-009).
//!
//! A [`ProvenanceRecord`] carries no authorization verdict of its own —
//! that is policy's job (F-M1-004). It only answers "what evidence
//! accompanied this request," never "was it allowed." This is the seam
//! `ComputeRequest`'s own module docs point to: `ComputeRequest` "carries
//! no identity/provenance of *who* is asking... composed alongside this
//! type by its callers, not folded into it" — [`ProvenanceRecord`] is
//! that composition.

use serde::{Deserialize, Serialize};

use crate::identity::ExecutionContext;
use crate::resource::ComputeRequest;

/// The observed execution context that accompanied one [`ComputeRequest`].
///
/// Constructing a `ProvenanceRecord` never inspects or validates its
/// evidence — a record built from all-`Missing` evidence is exactly as
/// constructible as one built from all-`KernelObserved` evidence. That is
/// intentional: this type's job is to preserve what was actually
/// observed for later reconstruction, not to pre-judge it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceRecord {
    pub context: ExecutionContext,
    pub request: ComputeRequest,
}

impl ProvenanceRecord {
    #[must_use]
    pub fn new(context: ExecutionContext, request: ComputeRequest) -> Self {
        Self { context, request }
    }
}
