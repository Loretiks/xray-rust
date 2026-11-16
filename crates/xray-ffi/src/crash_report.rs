use super::*;
use std::path::Path;
use xray_core_rs::crash_report;

/// Mirrors the process-wide crash report to `xray-crash-report.json` in
/// `directory`, or stops mirroring it when `directory` is null (ABI 1.20,
/// `CRASH_REPORTS`). Process-wide: call it before or after any core exists.
/// See the C header for the file's life cycle.
///
/// # Safety
///
/// `directory` must be null or point to a NUL-terminated string that stays
/// unchanged during the call. If `error` is non-null, it must point to an
/// initialized `*mut XrayError` value that is either null or a live error
/// pointer returned by this library. This function may free and replace that
/// error pointer.
#[no_mangle]
pub unsafe extern "C" fn xray_set_crash_report_directory(
    directory: *const c_char,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        ffi_result_status(error, || {
            clear_error(error);
            crash_report::install_panic_hook();
            let directory = if directory.is_null() {
                None
            } else {
                Some(required_utf8_argument(
                    directory,
                    "crash report directory",
                    error,
                )?)
            };
            // The path is the host's own; the message leaves it out anyway,
            // since a container path can identify the installation.
            crash_report::set_report_directory(directory.map(Path::new)).map_err(|source| {
                set_error(
                    error,
                    XrayStatus::RuntimeError,
                    format!("crash report directory is not usable: {source}"),
                );
                XrayStatus::RuntimeError
            })?;
            Ok(XrayStatus::Ok)
        })
    }
}

/// Copies the process-wide crash events recorded since the last take as a
/// JSON document and marks them taken (ABI 1.20, `CRASH_REPORTS`).
///
/// A null `buffer` with `buffer_len == 0` is a size query that takes
/// nothing. Otherwise the document is taken only when it fits with its
/// trailing NUL; `BufferTooSmall` leaves the events in place and stores the
/// required length, excluding the NUL, in `written`.
///
/// # Safety
///
/// `written` must point to one writable `usize`. When non-null, `buffer`
/// must point to `buffer_len` writable bytes that do not overlap `written`.
/// If `error` is non-null, it must point to an initialized `*mut XrayError`
/// value that is either null or a live error pointer returned by this
/// library. This function may free and replace that error pointer.
#[no_mangle]
pub unsafe extern "C" fn xray_take_crash_reports(
    buffer: *mut c_char,
    buffer_len: usize,
    written: *mut usize,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        ffi_result_status(error, || {
            clear_error(error);
            crash_report::install_panic_hook();
            ensure_non_null(written, error, "crash reports length pointer is null")?;
            *written = 0;
            if buffer.is_null() {
                if buffer_len != 0 {
                    set_error(
                        error,
                        XrayStatus::NullArgument,
                        "crash reports buffer is null",
                    );
                    return Err(XrayStatus::NullArgument);
                }
                *written = crash_report::peek_json().len();
                return Ok(XrayStatus::Ok);
            }
            match crash_report::take_json_within(buffer_len.saturating_sub(1)) {
                Ok(json) => {
                    ptr::copy_nonoverlapping(json.as_ptr(), buffer.cast::<u8>(), json.len());
                    *buffer.add(json.len()) = 0;
                    *written = json.len();
                    Ok(XrayStatus::Ok)
                }
                Err(required) => {
                    *written = required;
                    set_error(
                        error,
                        XrayStatus::BufferTooSmall,
                        format!(
                            "crash reports buffer is {buffer_len} bytes; {} bytes are required",
                            required.saturating_add(1)
                        ),
                    );
                    Err(XrayStatus::BufferTooSmall)
                }
            }
        })
    }
}
