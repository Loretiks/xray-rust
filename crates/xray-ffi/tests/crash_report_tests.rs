//! The process-wide crash report (ABI 1.20). The tests share one recorder, so
//! each holds `SERIAL` and starts by taking what earlier tests left.

use std::ffi::{c_char, CStr, CString};
use std::fs;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::{Mutex, MutexGuard, PoisonError};

use serde_json::Value;
use xray_ffi::{
    xray_core_free, xray_core_new, xray_error_code, xray_error_free, xray_error_message,
    xray_ffi_capabilities, xray_set_crash_report_directory, xray_take_crash_reports, XrayError,
    XrayStatus, XRAY_FFI_CAPABILITY_CRASH_REPORTS,
};

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "{prefix}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time should be after epoch")
            .as_nanos()
    ));
    fs::create_dir_all(&dir).expect("temp dir should be created");
    dir
}

/// Takes the error left in `error`, returning its code and message.
fn take_error(error: &mut *mut XrayError) -> (XrayStatus, String) {
    assert!(!error.is_null(), "an error was reported");
    let taken = unsafe {
        (
            xray_error_code(*error),
            CStr::from_ptr(xray_error_message(*error))
                .to_str()
                .unwrap()
                .to_owned(),
        )
    };
    unsafe { xray_error_free(*error) };
    *error = ptr::null_mut();
    taken
}

fn set_directory(dir: Option<&Path>) -> XrayStatus {
    let dir = dir.map(|dir| CString::new(dir.to_str().unwrap()).unwrap());
    let mut error = ptr::null_mut();
    let status = unsafe {
        xray_set_crash_report_directory(
            dir.as_ref().map_or(ptr::null(), |dir| dir.as_ptr()),
            &mut error,
        )
    };
    if !error.is_null() {
        unsafe { xray_error_free(error) };
    }
    status
}

fn take() -> Value {
    let mut error = ptr::null_mut();
    let mut required = 0;
    let status = unsafe { xray_take_crash_reports(ptr::null_mut(), 0, &mut required, &mut error) };
    assert_eq!(status, XrayStatus::Ok);
    assert!(error.is_null());
    // Room for events that may arrive between the query and the take.
    let mut buffer = vec![0 as c_char; required + 64 * 1024];
    let mut written = 0;
    let status = unsafe {
        xray_take_crash_reports(buffer.as_mut_ptr(), buffer.len(), &mut written, &mut error)
    };
    assert_eq!(status, XrayStatus::Ok);
    let json = unsafe { CStr::from_ptr(buffer.as_ptr()) }.to_str().unwrap();
    assert_eq!(json.len(), written);
    serde_json::from_str(json).expect("the report is JSON")
}

fn events(document: &Value) -> &Vec<Value> {
    document["events"].as_array().expect("events array")
}

fn find<'a>(document: &'a Value, message: &str) -> Option<&'a Value> {
    events(document)
        .iter()
        .find(|event| event["message"] == message)
}

fn panic_on_a_thread(message: &'static str) {
    let joined = std::thread::Builder::new()
        .name("crash-test".to_owned())
        .spawn(move || panic!("{message}"))
        .unwrap()
        .join();
    assert!(joined.is_err());
}

fn read_report(path: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(path).expect("report file")).expect("report is JSON")
}

/// Any core installs the hook; these tests rely on it.
fn install_hook_through_a_core() {
    let mut error = ptr::null_mut();
    let core = unsafe { xray_core_new(&mut error) };
    assert!(!core.is_null());
    unsafe { xray_core_free(core) };
}

#[test]
fn crash_reports_are_advertised() {
    assert_ne!(
        xray_ffi_capabilities() & XRAY_FFI_CAPABILITY_CRASH_REPORTS,
        0
    );
    assert_eq!(XRAY_FFI_CAPABILITY_CRASH_REPORTS, 1 << 33);
}

#[test]
fn a_panic_in_a_spawned_task_is_recorded_and_a_take_clears_it() {
    let _serial = serial();
    install_hook_through_a_core();
    take();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("crash-test-worker")
        .build()
        .unwrap();
    let joined = runtime
        .block_on(async { tokio::spawn(async { panic!("ffi-task-marker for 192.0.2.10") }).await });
    assert!(joined.unwrap_err().is_panic());

    let document = take();
    assert_eq!(document["schemaVersion"], 1);
    assert_eq!(document["pid"], std::process::id());
    assert!(document["startedUnixMs"].as_u64().unwrap() > 0);
    let event = find(&document, "ffi-task-marker for <redacted-ip>").expect("the panic");
    assert_eq!(event["kind"], "panic");
    assert_eq!(event["count"], 1);
    assert!(event["location"]
        .as_str()
        .unwrap()
        .starts_with("crates/xray-ffi/tests/crash_report_tests.rs:"));
    assert_eq!(event["thread"], "crash-test-worker");
    assert!(event["unixMs"].as_u64().unwrap() >= document["startedUnixMs"].as_u64().unwrap());
    if cfg!(all(
        any(
            target_vendor = "apple",
            target_os = "linux",
            target_os = "android"
        ),
        not(target_arch = "arm")
    )) {
        let backtrace = event["backtrace"].as_str().expect("a backtrace");
        let frames = backtrace.lines().count();
        assert!((1..=32).contains(&frames), "{frames} frames");
        assert!(backtrace.len() <= 8 * 1024);
    }

    let again = take();
    assert!(
        find(&again, "ffi-task-marker for <redacted-ip>").is_none(),
        "a take clears what it returned"
    );
}

#[test]
fn the_ring_is_bounded_and_counts_what_it_dropped() {
    let _serial = serial();
    install_hook_through_a_core();
    take();

    const MESSAGES: [&str; 20] = [
        "ring-00", "ring-01", "ring-02", "ring-03", "ring-04", "ring-05", "ring-06", "ring-07",
        "ring-08", "ring-09", "ring-10", "ring-11", "ring-12", "ring-13", "ring-14", "ring-15",
        "ring-16", "ring-17", "ring-18", "ring-19",
    ];
    for message in MESSAGES {
        panic_on_a_thread(message);
    }
    panic_on_a_thread("ring-19");

    let document = take();
    let messages = events(&document)
        .iter()
        .map(|event| event["message"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(messages, MESSAGES[4..]);
    assert_eq!(document["droppedEvents"], 4);
    assert_eq!(events(&document).last().unwrap()["count"], 2);
    assert_eq!(events(&document).last().unwrap()["thread"], "crash-test");
}

#[test]
fn a_short_buffer_or_size_query_takes_nothing() {
    let _serial = serial();
    install_hook_through_a_core();
    take();
    panic_on_a_thread("short-buffer-marker");

    let mut error = ptr::null_mut();
    let mut required = 0;
    let status = unsafe { xray_take_crash_reports(ptr::null_mut(), 0, &mut required, &mut error) };
    assert_eq!(status, XrayStatus::Ok);
    assert!(required > 0);

    let mut buffer = vec![0 as c_char; required];
    let mut written = 0;
    let status = unsafe {
        xray_take_crash_reports(buffer.as_mut_ptr(), buffer.len(), &mut written, &mut error)
    };
    assert_eq!(status, XrayStatus::BufferTooSmall);
    assert_eq!(written, required, "the NUL does not fit");
    assert_eq!(take_error(&mut error).0, XrayStatus::BufferTooSmall);

    assert!(find(&take(), "short-buffer-marker").is_some());
}

#[test]
fn the_report_file_is_written_readable_and_moved_aside() {
    let _serial = serial();
    install_hook_through_a_core();
    take();
    let dir = unique_temp_dir("xray-ffi-crash-report");
    let other = unique_temp_dir("xray-ffi-crash-report-other");
    let current = dir.join("xray-crash-report.json");
    let previous = dir.join("xray-crash-report.previous.json");
    fs::write(&current, "left by a previous process").unwrap();

    assert_eq!(set_directory(Some(&dir)), XrayStatus::Ok);
    assert_eq!(
        fs::read_to_string(&previous).unwrap(),
        "left by a previous process"
    );
    let document = read_report(&current);
    assert_eq!(document["schemaVersion"], 1);
    assert_eq!(document["pid"], std::process::id());

    panic_on_a_thread("file-marker");
    let document = read_report(&current);
    let event = find(&document, "file-marker").expect("a new panic is written at once");
    assert_eq!(event["kind"], "panic");
    assert!(event["backtrace"].is_string() || event["backtrace"].is_null());

    // A take leaves the file alone: it is the record of this process.
    assert!(find(&take(), "file-marker").is_some());
    assert!(find(&read_report(&current), "file-marker").is_some());

    // The same directory again does not move the file aside; another one,
    // then this one again, does.
    assert_eq!(set_directory(Some(&dir)), XrayStatus::Ok);
    assert_eq!(
        fs::read_to_string(&previous).unwrap(),
        "left by a previous process"
    );
    assert_eq!(set_directory(Some(&other)), XrayStatus::Ok);
    assert_eq!(set_directory(Some(&dir)), XrayStatus::Ok);
    assert!(find(&read_report(&previous), "file-marker").is_some());

    // Without a directory nothing is written.
    assert_eq!(set_directory(None), XrayStatus::Ok);
    let before = fs::read_to_string(&current).unwrap();
    panic_on_a_thread("after-file-marker");
    assert_eq!(fs::read_to_string(&current).unwrap(), before);
    assert!(find(&take(), "after-file-marker").is_some());

    fs::remove_dir_all(dir).unwrap();
    fs::remove_dir_all(other).unwrap();
}

#[test]
fn arguments_are_validated() {
    let _serial = serial();
    let mut error = ptr::null_mut();

    let status =
        unsafe { xray_take_crash_reports(ptr::null_mut(), 0, ptr::null_mut(), &mut error) };
    assert_eq!(status, XrayStatus::NullArgument);
    take_error(&mut error);
    let mut written = 7;
    let status = unsafe { xray_take_crash_reports(ptr::null_mut(), 8, &mut written, &mut error) };
    assert_eq!(status, XrayStatus::NullArgument);
    assert_eq!(written, 0);
    take_error(&mut error);

    let empty = CString::new("").unwrap();
    let status = unsafe { xray_set_crash_report_directory(empty.as_ptr(), &mut error) };
    assert_eq!(status, XrayStatus::InvalidArgument);
    take_error(&mut error);

    let invalid = [0xffu8 as c_char, 0];
    let status = unsafe { xray_set_crash_report_directory(invalid.as_ptr(), &mut error) };
    assert_eq!(status, XrayStatus::InvalidUtf8);
    take_error(&mut error);

    let missing = unique_temp_dir("xray-ffi-crash-report-missing").join("missing-dir-name");
    let path = CString::new(missing.to_str().unwrap()).unwrap();
    let status = unsafe { xray_set_crash_report_directory(path.as_ptr(), &mut error) };
    assert_eq!(status, XrayStatus::RuntimeError);
    let (code, message) = take_error(&mut error);
    assert_eq!(code, XrayStatus::RuntimeError);
    assert!(!message.contains("missing-dir-name"), "{message}");
    fs::remove_dir_all(missing.parent().unwrap()).unwrap();
}
