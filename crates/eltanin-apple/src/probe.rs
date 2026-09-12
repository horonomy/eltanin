//! Real Metal compute probe: dispatches a trivial compute kernel on the
//! system GPU device and reads back its result.
//!
//! This is deliberately **not** a `ComputeBackend` method — see this
//! crate's `lib.rs` module docs. `AppleBackend::discover` must stay
//! cheap and side-effect-free (no kernel dispatch), so this lives as a
//! standalone function instead of growing the trait.

use eltanin_backend::contract::BackendError;
#[cfg(not(target_os = "macos"))]
use eltanin_core::resource::Capability;

/// The outcome of a successful real Metal compute-probe run.
#[derive(Debug, Clone, PartialEq)]
pub struct ComputeProbeReport {
    /// The name of the Metal device the probe ran on.
    pub device_name: String,
    /// The device's `registryID` (see `crate::device::DeviceSnapshot`) —
    /// a stable-enough local identifier for this device on this host,
    /// included so evidence built from this report can be correlated
    /// with `AppleBackend::discover`'s own reported identity.
    pub registry_id: u64,
    /// Whether the device reported a unified (shared-with-host) memory
    /// architecture, per `MTLDevice::hasUnifiedMemory`.
    pub has_unified_memory: bool,
    /// A deterministic (non-cryptographic) 64-bit hash of the kernel's
    /// input buffer, computed by [`fnv1a_64`] — lets a caller assert two
    /// runs used bit-identical input without embedding the raw floats.
    pub input_hash: u64,
    /// How many input/output elements the kernel dispatched over.
    pub element_count: usize,
    /// How many output elements were checked against the expected
    /// doubled value.
    pub verified_elements: usize,
}

/// A small, dependency-free deterministic hash (FNV-1a, 64-bit) used to
/// give machine-readable evidence a stable "input fingerprint" without
/// pulling in a cryptographic-hash crate for a non-security purpose (see
/// this module's doc comment: this probe never makes a security claim,
/// only a determinism/audit-trail one).
#[must_use]
pub fn fnv1a_64(bytes: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET_BASIS;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

/// Compile a trivial inline kernel that doubles each input element,
/// dispatch it on the system's default Metal device, read back the
/// result, and assert it is correct.
///
/// This proves genuine Metal GPU compute happened — it is deliberately
/// **not** a device-level protection claim (see this crate's `lib.rs`
/// docs and ADR 0006/0007): nothing here authorizes, enforces, or
/// revokes anything.
///
/// # Errors
///
/// Returns [`BackendError::Unsupported`] on any non-macOS target, or
/// [`BackendError::Transient`] if no Metal device is currently present,
/// if kernel compilation/pipeline creation fails, or if the readback
/// does not match the expected doubled values.
#[cfg(target_os = "macos")]
pub fn run_compute_probe() -> Result<ComputeProbeReport, BackendError> {
    imp::run_compute_probe()
}

/// # Errors
///
/// Always returns `BackendError::Unsupported { capability:
/// Capability::DiscoverResource }` — the same capability
/// `AppleBackend::discover` reports as `Unsupported` on this target, for
/// the same reason: no `objc2-metal` dependency exists in a non-macOS
/// build's dependency graph (see this crate's `Cargo.toml`), so no
/// Metal call — including discovering whether a device exists at all —
/// is ever attempted here. This is deliberately not
/// `Capability::ControlledLaunch`: that dimension is
/// `SupportState::NotEvaluated` (HORO-1013's scope, not claimed either
/// way by this crate — see `crate::backend::snapshot_to_resource`), so
/// this error must not assert a *structural* absence
/// (`BackendError::Unsupported`'s documented meaning) for a dimension
/// this crate has explicitly not evaluated.
#[cfg(not(target_os = "macos"))]
pub fn run_compute_probe() -> Result<ComputeProbeReport, BackendError> {
    Err(BackendError::Unsupported {
        capability: Capability::DiscoverResource,
    })
}

#[cfg(target_os = "macos")]
mod imp {
    use objc2::rc::Retained;
    use objc2_foundation::NSString;
    use objc2_metal::{
        MTLBuffer, MTLCommandBuffer, MTLCommandEncoder, MTLCommandQueue, MTLComputeCommandEncoder,
        MTLCopyAllDevices, MTLDevice, MTLLibrary, MTLResourceOptions, MTLSize,
    };

    use eltanin_backend::contract::BackendError;

    use super::{fnv1a_64, ComputeProbeReport};

    /// Doubles each `float` in `input`, writing the result to `output`.
    /// One thread per element — `dispatchThreadgroups_threadsPerThreadgroup`
    /// below sizes the grid to exactly `ELEMENT_COUNT` threads.
    const KERNEL_SOURCE: &str = "
        #include <metal_stdlib>
        using namespace metal;

        kernel void double_elements(device const float* input [[buffer(0)]],
                                     device float* output [[buffer(1)]],
                                     uint id [[thread_position_in_grid]]) {
            output[id] = input[id] * 2.0;
        }
    ";

    const ELEMENT_COUNT: usize = 16;

    fn transient(message: impl Into<String>) -> BackendError {
        BackendError::Transient {
            message: message.into(),
        }
    }

    #[allow(unsafe_code)]
    pub(super) fn run_compute_probe() -> Result<ComputeProbeReport, BackendError> {
        let devices = MTLCopyAllDevices();
        let device = devices
            .iter()
            .next()
            .ok_or_else(|| transient("no Metal device is currently present"))?;
        let device_name = device.name().to_string();
        let registry_id = device.registryID();
        let has_unified_memory = device.hasUnifiedMemory();

        let queue = device
            .newCommandQueue()
            .ok_or_else(|| transient("Metal device could not create a command queue"))?;

        let source = NSString::from_str(KERNEL_SOURCE);
        let library: Retained<_> = device
            .newLibraryWithSource_options_error(&source, None)
            .map_err(|e| transient(format!("Metal kernel source failed to compile: {e}")))?;
        let function = library
            .newFunctionWithName(&NSString::from_str("double_elements"))
            .ok_or_else(|| {
                transient("compiled Metal library has no \"double_elements\" function")
            })?;
        let pipeline = device
            .newComputePipelineStateWithFunction_error(&function)
            .map_err(|e| transient(format!("Metal compute pipeline creation failed: {e}")))?;

        // `ELEMENT_COUNT` is 16, so `i` is always exactly representable
        // as `f32` (whose mantissa covers integers up to 2^24) — no
        // precision loss is possible here despite the general lint.
        #[allow(clippy::cast_precision_loss)]
        let input: [f32; ELEMENT_COUNT] = std::array::from_fn(|i| i as f32);
        let byte_len = std::mem::size_of_val(&input);
        // A plain, safe byte-serialization of `input` (no `unsafe`
        // transmute needed) purely to feed the deterministic
        // fingerprint hash below.
        let input_bytes: Vec<u8> = input.iter().flat_map(|f| f.to_le_bytes()).collect();
        let input_hash = fnv1a_64(&input_bytes);

        let input_buffer = device
            .newBufferWithLength_options(byte_len, MTLResourceOptions::StorageModeShared)
            .ok_or_else(|| transient("Metal device could not allocate the input buffer"))?;
        let output_buffer = device
            .newBufferWithLength_options(byte_len, MTLResourceOptions::StorageModeShared)
            .ok_or_else(|| transient("Metal device could not allocate the output buffer"))?;

        // SAFETY: `input_buffer` was just allocated above with exactly
        // `byte_len` bytes and `MTLResourceOptions::StorageModeShared`
        // (host-visible unified memory), so `contents()` returns a valid,
        // writable pointer to at least `byte_len` bytes for the lifetime
        // of `input_buffer`, which outlives this write.
        unsafe {
            std::ptr::copy_nonoverlapping(
                input.as_ptr().cast::<u8>(),
                input_buffer.contents().as_ptr().cast::<u8>(),
                byte_len,
            );
        }

        let command_buffer = queue
            .commandBuffer()
            .ok_or_else(|| transient("Metal command queue could not create a command buffer"))?;
        let encoder = command_buffer
            .computeCommandEncoder()
            .ok_or_else(|| transient("Metal command buffer could not create a compute encoder"))?;

        encoder.setComputePipelineState(&pipeline);
        // SAFETY: `input_buffer`/`output_buffer` are each `byte_len`
        // bytes, matching what `double_elements` above declares as
        // `buffer(0)`/`buffer(1)` (a `float*` over the same element
        // count) — the encoder call itself only binds the buffer
        // reference; it does not dereference it. `offset: 0` is within
        // both buffers' bounds.
        unsafe {
            encoder.setBuffer_offset_atIndex(Some(&input_buffer), 0, 0);
            encoder.setBuffer_offset_atIndex(Some(&output_buffer), 0, 1);
        }
        encoder.dispatchThreadgroups_threadsPerThreadgroup(
            MTLSize {
                width: ELEMENT_COUNT,
                height: 1,
                depth: 1,
            },
            MTLSize {
                width: 1,
                height: 1,
                depth: 1,
            },
        );
        encoder.endEncoding();

        command_buffer.commit();
        command_buffer.waitUntilCompleted();

        // SAFETY: `output_buffer` is `byte_len` bytes of host-visible
        // shared-mode memory (allocated above), the GPU command buffer
        // that writes it has already completed
        // (`waitUntilCompleted` above happened-before this read), and
        // the constructed slice's length (`ELEMENT_COUNT` `f32`s) exactly
        // matches `byte_len`, so it does not read past the allocation.
        let output: &[f32] = unsafe {
            std::slice::from_raw_parts(
                output_buffer.contents().cast::<f32>().as_ptr(),
                ELEMENT_COUNT,
            )
        };

        for (i, &value) in output.iter().enumerate() {
            let expected = input[i] * 2.0;
            if (value - expected).abs() > f32::EPSILON {
                return Err(transient(format!(
                    "Metal compute probe produced wrong value at index {i}: expected \
                     {expected}, got {value}"
                )));
            }
        }

        Ok(ComputeProbeReport {
            device_name,
            registry_id,
            has_unified_memory,
            input_hash,
            element_count: ELEMENT_COUNT,
            verified_elements: ELEMENT_COUNT,
        })
    }
}
