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
    /// How many output elements were checked against the expected
    /// doubled value.
    pub verified_elements: usize,
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
/// Returns [`BackendError::Unsupported`] on any non-macOS target, or if
/// no Metal device is present, if kernel compilation/pipeline creation
/// fails, or if the readback does not match the expected doubled values.
#[cfg(target_os = "macos")]
pub fn run_compute_probe() -> Result<ComputeProbeReport, BackendError> {
    imp::run_compute_probe()
}

/// # Errors
///
/// Always returns [`BackendError::Unsupported`] — no `objc2-metal`
/// dependency exists in a non-macOS build's dependency graph (see this
/// crate's `Cargo.toml`), so no Metal call is ever attempted here.
#[cfg(not(target_os = "macos"))]
pub fn run_compute_probe() -> Result<ComputeProbeReport, BackendError> {
    Err(BackendError::Unsupported {
        capability: Capability::ControlledLaunch,
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
    use eltanin_core::resource::Capability;

    use super::ComputeProbeReport;

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

    fn unsupported() -> BackendError {
        BackendError::Unsupported {
            capability: Capability::ControlledLaunch,
        }
    }

    fn transient(message: impl Into<String>) -> BackendError {
        BackendError::Transient {
            message: message.into(),
        }
    }

    #[allow(unsafe_code)]
    pub(super) fn run_compute_probe() -> Result<ComputeProbeReport, BackendError> {
        let devices = MTLCopyAllDevices();
        let device = devices.iter().next().ok_or_else(unsupported)?;
        let device_name = device.name().to_string();

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
            verified_elements: ELEMENT_COUNT,
        })
    }
}
