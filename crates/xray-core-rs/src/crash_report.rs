//! Process-wide record of the failures that explain a tunnel that looks up
//! but no longer works, or a process that ended: panics, runtime tasks that
//! ended before the core stopped, a TUN descriptor pump that gave up, and
//! counted summaries of DNS-anchor and flow-budget failures.
//!
//! Events go to a ring of at most [`MAX_EVENTS`] that a host drains with
//! [`take_json_within`]. Once [`set_report_directory`] names a directory, the
//! ring is also mirrored to [`REPORT_FILE_NAME`] there, written whole to a
//! temporary file and renamed over the old one, so the next process can read
//! why this one ended. Messages pass through the redaction below: addresses,
//! domains, URLs, UUIDs and key-like tokens never reach the ring or the file.

use std::any::Any;
use std::cell::Cell;
use std::collections::VecDeque;
use std::fmt;
use std::fs;
use std::future::Future;
use std::io::{self, Write as _};
use std::net::{IpAddr, SocketAddr};
use std::panic::{AssertUnwindSafe, Location, PanicHookInfo};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, Once, OnceLock, PoisonError};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use futures_util::FutureExt as _;
use tokio::sync::watch;
use tokio::task::JoinError;

/// Version of the JSON document that [`take_json_within`] returns and the
/// report file holds.
pub const SCHEMA_VERSION: u32 = 1;
/// Events the ring keeps. A new event pushes out the oldest one.
pub const MAX_EVENTS: usize = 16;
/// Longest message kept, in UTF-8 bytes, before JSON escaping.
pub const MAX_MESSAGE_BYTES: usize = 1024;
/// Longest source location kept.
pub const MAX_LOCATION_BYTES: usize = 256;
/// Longest thread name kept.
pub const MAX_THREAD_BYTES: usize = 64;
/// Frames a panic's backtrace keeps.
pub const MAX_BACKTRACE_FRAMES: usize = 32;
/// Longest backtrace kept.
pub const MAX_BACKTRACE_BYTES: usize = 8 * 1024;
/// Largest report file. The oldest events are left out of the file, and
/// counted in its `droppedEvents`, when the ring does not fit.
pub const MAX_REPORT_FILE_BYTES: usize = 64 * 1024;
/// The report of the running process, in the configured directory.
pub const REPORT_FILE_NAME: &str = "xray-crash-report.json";
/// The report the previous process left, moved aside when a process first
/// configures the directory.
pub const PREVIOUS_REPORT_FILE_NAME: &str = "xray-crash-report.previous.json";

const TEMPORARY_REPORT_FILE_NAME: &str = ".xray-crash-report.json.tmp";
/// A new panic rewrites the file at once. Anything else, a repeat of an
/// event included, rewrites it at most this often; a skipped write is made by
/// the next event or take after the interval.
const FILE_WRITE_INTERVAL_MS: u64 = 250;
/// A summary counter adds what it counted to the ring at most this often.
/// The first count after a quiet interval is added at once.
const SUMMARY_INTERVAL_MS: u64 = 5_000;
const NEVER: u64 = u64::MAX;
const MAX_SYMBOL_BYTES: usize = 96;
const MAX_FRAME_LINE_BYTES: usize = 256;
const TRUNCATION_MARK: &str = "...";

/// What an event reports. Its JSON `kind` is [`CrashEventKind::as_str`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CrashEventKind {
    /// A panic, recorded by the panic hook with its location, thread and
    /// backtrace. One that unwinds ends the task or thread it ran on; one
    /// that cannot unwind aborts the process right after.
    Panic,
    /// A runtime task ended with a panic. The message names the task.
    TaskPanic,
    /// A runtime task that serves until the core stops returned before.
    TaskExit,
    /// The TUN descriptor read pump stopped on an I/O error: no packet from
    /// the system reaches the core any more.
    TunFdReadExit,
    /// The TUN descriptor write pump stopped on an I/O error: no packet from
    /// the core reaches the system any more.
    TunFdWriteExit,
    /// Queries to the TUN DNS anchor failed on every upstream and were
    /// answered SERVFAIL. Counted, not one event per query.
    DnsAnchorFailure,
    /// New TUN flows or DNS queries were refused because a flow budget was
    /// exhausted. Counted, not one event per flow.
    FlowBudgetExhausted,
}

impl CrashEventKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Panic => "panic",
            Self::TaskPanic => "taskPanic",
            Self::TaskExit => "taskExit",
            Self::TunFdReadExit => "tunFdReadExit",
            Self::TunFdWriteExit => "tunFdWriteExit",
            Self::DnsAnchorFailure => "dnsAnchorFailure",
            Self::FlowBudgetExhausted => "flowBudgetExhausted",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CrashEvent {
    kind: CrashEventKind,
    message: String,
    location: Option<String>,
    thread: Option<String>,
    backtrace: Option<String>,
    first_unix_ms: u64,
    unix_ms: u64,
    count: u64,
    sequence: u64,
}

struct NewEvent {
    kind: CrashEventKind,
    message: String,
    location: Option<String>,
    thread: Option<String>,
    backtrace: Option<String>,
    count: u64,
}

struct ReportFile {
    directory: PathBuf,
    current: PathBuf,
    temporary: PathBuf,
    /// Reserved once, so writing the report from the panic hook does not
    /// allocate.
    buffer: Vec<u8>,
    last_write_ms: u64,
    dirty: bool,
}

impl ReportFile {
    fn new(directory: &Path) -> Self {
        Self {
            directory: directory.to_path_buf(),
            current: directory.join(REPORT_FILE_NAME),
            temporary: directory.join(TEMPORARY_REPORT_FILE_NAME),
            buffer: Vec::with_capacity(MAX_REPORT_FILE_BYTES),
            last_write_ms: NEVER,
            dirty: false,
        }
    }
}

struct Recorder {
    events: VecDeque<CrashEvent>,
    next_sequence: u64,
    /// Events up to this sequence were returned by a take.
    taken_through: u64,
    /// Events pushed out of the ring before a take returned them, since the
    /// last take.
    dropped_since_take: u64,
    /// Events pushed out of the ring, taken or not.
    evicted: u64,
    started_unix_ms: u64,
    file: Option<ReportFile>,
}

impl Recorder {
    const fn new() -> Self {
        Self {
            events: VecDeque::new(),
            next_sequence: 1,
            taken_through: 0,
            dropped_since_take: 0,
            evicted: 0,
            started_unix_ms: 0,
            file: None,
        }
    }

    /// Adds `event`, or counts it on an equal event no take has returned
    /// yet. Returns whether the ring holds a new event.
    fn push(&mut self, event: NewEvent, now: u64) -> bool {
        let taken_through = self.taken_through;
        if let Some(existing) = self.events.iter_mut().rev().find(|existing| {
            existing.sequence > taken_through
                && existing.kind == event.kind
                && existing.message == event.message
                && existing.location == event.location
        }) {
            existing.count = existing.count.saturating_add(event.count);
            existing.unix_ms = now;
            if existing.backtrace.is_none() {
                existing.backtrace = event.backtrace;
            }
            if existing.thread.is_none() {
                existing.thread = event.thread;
            }
            return false;
        }
        if self.events.len() >= MAX_EVENTS {
            // Sequences grow front to back, so the taken events are the
            // oldest and leave first.
            if let Some(evicted) = self.events.pop_front() {
                self.evicted = self.evicted.saturating_add(1);
                if evicted.sequence > taken_through {
                    self.dropped_since_take = self.dropped_since_take.saturating_add(1);
                }
            }
        }
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.events.push_back(CrashEvent {
            kind: event.kind,
            message: event.message,
            location: event.location,
            thread: event.thread,
            backtrace: event.backtrace,
            first_unix_ms: now,
            unix_ms: now,
            count: event.count,
            sequence,
        });
        true
    }

    fn header(&self, dropped_events: u64) -> DocumentHeader {
        DocumentHeader {
            pid: std::process::id(),
            started_unix_ms: self.started_unix_ms,
            dropped_events,
        }
    }

    fn pending_json(&self) -> String {
        let taken_through = self.taken_through;
        let mut json = String::new();
        // Writing to a String cannot fail.
        let _ = write_document(
            &mut json,
            &self.header(self.dropped_since_take),
            self.events
                .iter()
                .filter(|event| event.sequence > taken_through),
        );
        json
    }

    /// Returns the events no take has returned yet and marks them taken,
    /// when their document is at most `limit` bytes; otherwise its length,
    /// leaving them pending.
    fn take_within(&mut self, limit: usize) -> Result<String, usize> {
        let json = self.pending_json();
        if json.len() > limit {
            return Err(json.len());
        }
        self.taken_through = self.next_sequence.saturating_sub(1);
        self.dropped_since_take = 0;
        Ok(json)
    }

    /// Mirrors the ring to the report file: at once when `force`, otherwise
    /// at most every [`FILE_WRITE_INTERVAL_MS`]. Best effort.
    fn persist(&mut self, now_ms: u64, force: bool) {
        let Some(mut file) = self.file.take() else {
            return;
        };
        let due = file.last_write_ms == NEVER
            || now_ms.saturating_sub(file.last_write_ms) >= FILE_WRITE_INTERVAL_MS;
        if force || due {
            let _ = self.write_file(&mut file);
            file.last_write_ms = now_ms;
            file.dirty = false;
        } else {
            file.dirty = true;
        }
        self.file = Some(file);
    }

    /// Makes a write [`Self::persist`] put off.
    fn persist_if_dirty(&mut self, now_ms: u64) {
        if self.file.as_ref().is_some_and(|file| file.dirty) {
            self.persist(now_ms, true);
        }
    }

    fn write_file(&self, file: &mut ReportFile) -> io::Result<()> {
        // The ring holds at most MAX_EVENTS bounded events; leave out the
        // oldest until the document fits the reserved buffer.
        let mut omitted = 0usize;
        loop {
            file.buffer.clear();
            let header = self.header(self.evicted.saturating_add(omitted as u64));
            let mut sink = BoundedSink {
                buffer: &mut file.buffer,
                limit: MAX_REPORT_FILE_BYTES,
            };
            if write_document(&mut sink, &header, self.events.iter().skip(omitted)).is_ok() {
                break;
            }
            if omitted >= self.events.len() {
                return Err(io::Error::other("crash report does not fit its file"));
            }
            omitted += 1;
        }
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut temporary = options.open(&file.temporary)?;
        temporary.write_all(&file.buffer)?;
        drop(temporary);
        fs::rename(&file.temporary, &file.current)
    }

    /// Mirrors the ring into `directory` from now on, or stops mirroring it.
    /// A directory other than the current one first has the report a
    /// previous process left moved to [`PREVIOUS_REPORT_FILE_NAME`].
    fn set_directory(&mut self, directory: Option<&Path>, now_ms: u64) -> io::Result<()> {
        let Some(directory) = directory else {
            self.file = None;
            return Ok(());
        };
        // A directory that cannot hold the report is not kept.
        let previous = self.file.take();
        let mut file = match previous {
            Some(file) if file.directory == directory => file,
            _ => {
                if !fs::metadata(directory)?.is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::NotADirectory,
                        "crash report path is not a directory",
                    ));
                }
                match fs::rename(
                    directory.join(REPORT_FILE_NAME),
                    directory.join(PREVIOUS_REPORT_FILE_NAME),
                ) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
                ReportFile::new(directory)
            }
        };
        self.write_file(&mut file)?;
        file.last_write_ms = now_ms;
        file.dirty = false;
        self.file = Some(file);
        Ok(())
    }
}

struct DocumentHeader {
    pid: u32,
    started_unix_ms: u64,
    dropped_events: u64,
}

fn write_document<'a, W: fmt::Write>(
    out: &mut W,
    header: &DocumentHeader,
    events: impl Iterator<Item = &'a CrashEvent>,
) -> fmt::Result {
    write!(
        out,
        "{{\"schemaVersion\":{SCHEMA_VERSION},\"pid\":{},\"startedUnixMs\":{},\"droppedEvents\":{},\"events\":[",
        header.pid, header.started_unix_ms, header.dropped_events
    )?;
    for (index, event) in events.enumerate() {
        if index > 0 {
            out.write_char(',')?;
        }
        write_event(out, event)?;
    }
    out.write_str("]}")
}

fn write_event<W: fmt::Write>(out: &mut W, event: &CrashEvent) -> fmt::Result {
    out.write_str("{\"kind\":")?;
    write_json_string(out, event.kind.as_str())?;
    out.write_str(",\"message\":")?;
    write_json_string(out, &event.message)?;
    out.write_str(",\"location\":")?;
    write_optional_json_string(out, event.location.as_deref())?;
    out.write_str(",\"thread\":")?;
    write_optional_json_string(out, event.thread.as_deref())?;
    out.write_str(",\"backtrace\":")?;
    write_optional_json_string(out, event.backtrace.as_deref())?;
    write!(
        out,
        ",\"unixMs\":{},\"firstUnixMs\":{},\"count\":{}}}",
        event.unix_ms, event.first_unix_ms, event.count
    )
}

fn write_optional_json_string<W: fmt::Write>(out: &mut W, value: Option<&str>) -> fmt::Result {
    match value {
        Some(value) => write_json_string(out, value),
        None => out.write_str("null"),
    }
}

fn write_json_string<W: fmt::Write>(out: &mut W, value: &str) -> fmt::Result {
    out.write_char('"')?;
    let mut unescaped_from = 0;
    for (index, ch) in value.char_indices() {
        let escape = match ch {
            '"' => "\\\"",
            '\\' => "\\\\",
            '\n' => "\\n",
            '\r' => "\\r",
            '\t' => "\\t",
            ch if u32::from(ch) < 0x20 => "",
            _ => continue,
        };
        out.write_str(&value[unescaped_from..index])?;
        if escape.is_empty() {
            write!(out, "\\u{:04x}", u32::from(ch))?;
        } else {
            out.write_str(escape)?;
        }
        unescaped_from = index + ch.len_utf8();
    }
    out.write_str(&value[unescaped_from..])?;
    out.write_char('"')
}

/// A `fmt::Write` over a reserved buffer that refuses to grow past `limit`.
struct BoundedSink<'a> {
    buffer: &'a mut Vec<u8>,
    limit: usize,
}

impl fmt::Write for BoundedSink<'_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        if self.buffer.len().saturating_add(value.len()) > self.limit {
            return Err(fmt::Error);
        }
        self.buffer.extend_from_slice(value.as_bytes());
        Ok(())
    }
}

static RECORDER: Mutex<Recorder> = Mutex::new(Recorder::new());

/// Serializes the tests that take from the process-wide recorder.
#[cfg(test)]
pub(crate) static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

thread_local! {
    static RECORDING: Cell<bool> = const { Cell::new(false) };
}

/// Marks this thread as inside the recorder, so a panic raised while it
/// holds the lock is not recorded by the hook on the same thread, which
/// would deadlock.
struct RecordingGuard;

impl RecordingGuard {
    fn enter() -> Option<Self> {
        RECORDING
            .try_with(|recording| (!recording.replace(true)).then_some(Self))
            .ok()
            .flatten()
    }
}

impl Drop for RecordingGuard {
    fn drop(&mut self) {
        let _ = RECORDING.try_with(|recording| recording.set(false));
    }
}

fn recorder() -> MutexGuard<'static, Recorder> {
    let mut recorder = RECORDER.lock().unwrap_or_else(PoisonError::into_inner);
    if recorder.started_unix_ms == 0 {
        recorder.started_unix_ms = unix_ms();
    }
    recorder
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Milliseconds on a clock that does not jump, for the rate limits.
fn monotonic_ms() -> u64 {
    static BASE: OnceLock<Instant> = OnceLock::new();
    u64::try_from(BASE.get_or_init(Instant::now).elapsed().as_millis()).unwrap_or(u64::MAX - 1)
}

/// Installs, once per process, a panic hook that records every panic, then
/// calls the hook that was installed before it, so panics are still printed.
/// Calling it again does nothing; a hook installed later replaces both.
pub fn install_panic_hook() {
    static INSTALL: Once = Once::new();
    if std::thread::panicking() {
        return;
    }
    INSTALL.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            record_panic(info);
            previous(info);
        }));
    });
    if let Some(_guard) = RecordingGuard::enter() {
        drop(recorder());
    }
}

/// Mirrors the events to [`REPORT_FILE_NAME`] in `directory`, which must
/// exist, or stops mirroring them with `None`. The first call for a directory
/// moves the report a previous process left there to
/// [`PREVIOUS_REPORT_FILE_NAME`], then writes the current events at once,
/// so a process with nothing to report leaves an empty report. On error
/// nothing is mirrored until a later call succeeds.
pub fn set_report_directory(directory: Option<&Path>) -> io::Result<()> {
    let Some(_guard) = RecordingGuard::enter() else {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "the crash recorder is busy on this thread",
        ));
    };
    let mut recorder = recorder();
    flush_summaries(&mut recorder, unix_ms());
    recorder.set_directory(directory, monotonic_ms())
}

/// The report file of the running process in `directory`.
pub fn report_file_path(directory: &Path) -> PathBuf {
    directory.join(REPORT_FILE_NAME)
}

/// The report file the previous process left in `directory`.
pub fn previous_report_file_path(directory: &Path) -> PathBuf {
    directory.join(PREVIOUS_REPORT_FILE_NAME)
}

/// The document a take would return now, without taking anything.
pub fn peek_json() -> String {
    let Some(_guard) = RecordingGuard::enter() else {
        return String::new();
    };
    let mut recorder = recorder();
    if flush_summaries(&mut recorder, unix_ms()) {
        recorder.persist(monotonic_ms(), false);
    }
    recorder.pending_json()
}

/// Returns the events recorded since the last take and marks them taken, if
/// their JSON document is at most `limit` bytes; otherwise returns its
/// length and keeps them. The report file keeps taken events until newer
/// ones push them out of the ring.
pub fn take_json_within(limit: usize) -> Result<String, usize> {
    let Some(_guard) = RecordingGuard::enter() else {
        return Err(0);
    };
    let mut recorder = recorder();
    let flushed = flush_summaries(&mut recorder, unix_ms());
    // The file is a record of the process: bring it up to date, whatever the
    // take returns.
    if flushed {
        recorder.persist(monotonic_ms(), true);
    } else {
        recorder.persist_if_dirty(monotonic_ms());
    }
    recorder.take_within(limit)
}

/// [`take_json_within`] without a limit.
pub fn take_json() -> String {
    take_json_within(usize::MAX).unwrap_or_default()
}

#[inline(never)]
fn record_panic(info: &PanicHookInfo<'_>) {
    let Some(_guard) = RecordingGuard::enter() else {
        return;
    };
    // Captured before the lock, which another thread may hold.
    let backtrace = capture_backtrace();
    let message = redact(
        info.payload_as_str().unwrap_or("Box<dyn Any>"),
        MAX_MESSAGE_BYTES,
    );
    let location = info.location().map(format_location);
    let thread = current_thread_name();
    let now = unix_ms();
    let mut recorder = recorder();
    let added = recorder.push(
        NewEvent {
            kind: CrashEventKind::Panic,
            message,
            location,
            thread,
            backtrace,
            count: 1,
        },
        now,
    );
    // A panic may be the last thing this process does.
    recorder.persist(monotonic_ms(), added);
}

/// Records a critical runtime event at the caller's location. `message` is
/// redacted and bounded here.
#[track_caller]
pub(crate) fn record(kind: CrashEventKind, message: &str) {
    record_event(
        kind,
        redact(message, MAX_MESSAGE_BYTES),
        Some(format_location(Location::caller())),
        current_thread_name(),
    );
}

fn record_event(
    kind: CrashEventKind,
    message: String,
    location: Option<String>,
    thread: Option<String>,
) {
    let Some(_guard) = RecordingGuard::enter() else {
        return;
    };
    let now = unix_ms();
    let mut recorder = recorder();
    recorder.push(
        NewEvent {
            kind,
            message,
            location,
            thread,
            backtrace: None,
            count: 1,
        },
        now,
    );
    recorder.persist(monotonic_ms(), false);
}

/// The message of a panic payload, as the default hook prints it.
fn panic_payload_message(payload: &(dyn Any + Send)) -> &str {
    payload
        .downcast_ref::<&'static str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("Box<dyn Any>")
}

/// Records that the runtime task `task` ended with a panic.
pub(crate) fn record_task_panic(task: &'static str, payload: &(dyn Any + Send)) {
    let message = format!("{task} panicked: {}", panic_payload_message(payload));
    record_event(
        CrashEventKind::TaskPanic,
        redact(&message, MAX_MESSAGE_BYTES),
        None,
        current_thread_name(),
    );
}

/// Records a joined task's panic, which the join would otherwise drop.
/// Cancellation is not a failure.
pub(crate) fn record_join_error(task: &'static str, error: JoinError) {
    if error.is_panic() {
        record_task_panic(task, error.into_panic().as_ref());
    }
}

/// Runs `future`, recording a panic of it as a panic of `task` before
/// letting it go on to the task's `JoinError`.
pub(crate) async fn catch_task_panic<F: Future>(task: &'static str, future: F) -> F::Output {
    match AssertUnwindSafe(future).catch_unwind().await {
        Ok(output) => output,
        Err(payload) => {
            record_task_panic(task, payload.as_ref());
            std::panic::resume_unwind(payload)
        }
    }
}

/// [`catch_task_panic`] for a task that serves until `shutdown` is signalled,
/// which also records the task returning before that.
pub(crate) async fn supervise_until_shutdown<F: Future<Output = ()>>(
    task: &'static str,
    shutdown: watch::Receiver<bool>,
    future: F,
) {
    catch_task_panic(task, future).await;
    // A dropped sender is the owner going away, a shutdown of its own.
    if !*shutdown.borrow() && shutdown.has_changed().is_ok() {
        record_event(
            CrashEventKind::TaskExit,
            format!("{task} stopped before the core was stopped"),
            None,
            current_thread_name(),
        );
    }
}

/// Counts occurrences of a failure that may repeat for every flow or query,
/// and adds them to the ring as one event with a count: the first at once,
/// then at most every [`SUMMARY_INTERVAL_MS`], and whatever is left on the
/// next take.
pub(crate) struct SummaryCounter {
    kind: CrashEventKind,
    message: &'static str,
    pending: AtomicU64,
    last_flush_ms: AtomicU64,
}

impl SummaryCounter {
    const fn new(kind: CrashEventKind, message: &'static str) -> Self {
        Self {
            kind,
            message,
            pending: AtomicU64::new(0),
            last_flush_ms: AtomicU64::new(NEVER),
        }
    }

    /// Counts one occurrence. Two atomic operations and a clock read unless
    /// the interval is over.
    pub(crate) fn note(&self) {
        if !self.count_one(monotonic_ms()) {
            return;
        }
        let Some(_guard) = RecordingGuard::enter() else {
            return;
        };
        let mut recorder = recorder();
        if self.flush_into(&mut recorder, unix_ms()) {
            recorder.persist(monotonic_ms(), false);
        }
    }

    /// Counts one occurrence and reports whether the count is due in the
    /// ring.
    fn count_one(&self, now_ms: u64) -> bool {
        self.pending.fetch_add(1, Ordering::Relaxed);
        let last = self.last_flush_ms.load(Ordering::Relaxed);
        if last != NEVER && now_ms.saturating_sub(last) < SUMMARY_INTERVAL_MS {
            return false;
        }
        self.last_flush_ms
            .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }

    fn flush_into(&self, recorder: &mut Recorder, now: u64) -> bool {
        let count = self.pending.swap(0, Ordering::Relaxed);
        if count == 0 {
            return false;
        }
        recorder.push(
            NewEvent {
                kind: self.kind,
                message: self.message.to_owned(),
                location: None,
                thread: None,
                backtrace: None,
                count,
            },
            now,
        );
        true
    }
}

/// New TUN TCP flows refused because the TCP, pending-open or DNS TCP flow
/// limit was reached.
pub(crate) static TUN_TCP_FLOW_BUDGET: SummaryCounter = SummaryCounter::new(
    CrashEventKind::FlowBudgetExhausted,
    "TUN TCP flow budget exhausted: new TCP flows were refused",
);
/// New TUN UDP flows or DNS queries dropped because the UDP flow or task
/// budget was exhausted.
pub(crate) static TUN_UDP_FLOW_BUDGET: SummaryCounter = SummaryCounter::new(
    CrashEventKind::FlowBudgetExhausted,
    "TUN UDP flow budget exhausted: new UDP flows or DNS queries were dropped",
);
/// Queries to the TUN DNS anchor that failed on every upstream.
pub(crate) static DNS_ANCHOR_FAILURES: SummaryCounter = SummaryCounter::new(
    CrashEventKind::DnsAnchorFailure,
    "every DNS upstream failed for queries to the TUN DNS anchor; they were answered SERVFAIL",
);

static SUMMARIES: [&SummaryCounter; 3] = [
    &TUN_TCP_FLOW_BUDGET,
    &TUN_UDP_FLOW_BUDGET,
    &DNS_ANCHOR_FAILURES,
];

/// Adds what every summary counter counted. Returns whether any did.
fn flush_summaries(recorder: &mut Recorder, now: u64) -> bool {
    SUMMARIES.iter().fold(false, |flushed, summary| {
        summary.flush_into(recorder, now) | flushed
    })
}

fn format_location(location: &Location<'_>) -> String {
    let mut file = location.file();
    // A dependency's location carries the build machine's registry path.
    if let Some(index) = file.find("/registry/src/") {
        let after_registry = &file[index + "/registry/src/".len()..];
        file = after_registry
            .split_once('/')
            .map_or(after_registry, |(_, crate_path)| crate_path);
    }
    let mut formatted = format!("{file}:{}:{}", location.line(), location.column());
    truncate_with_mark(&mut formatted, MAX_LOCATION_BYTES);
    formatted
}

fn current_thread_name() -> Option<String> {
    let mut name = os_thread_name()?;
    truncate_with_mark(&mut name, MAX_THREAD_BYTES);
    Some(name)
}

/// The OS thread name, read without `std::thread::current`, which must not
/// run once the thread's locals are gone.
#[cfg(target_vendor = "apple")]
fn os_thread_name() -> Option<String> {
    let mut buffer = [0 as libc::c_char; 64];
    // SAFETY: the buffer is writable for its length, and the call
    // NUL-terminates what it writes.
    let status = unsafe {
        libc::pthread_getname_np(libc::pthread_self(), buffer.as_mut_ptr(), buffer.len())
    };
    if status != 0 {
        return None;
    }
    // SAFETY: pthread_getname_np succeeded and wrote a NUL-terminated name.
    let name = unsafe { std::ffi::CStr::from_ptr(buffer.as_ptr()) };
    name.to_str()
        .ok()
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
}

#[cfg(not(target_vendor = "apple"))]
fn os_thread_name() -> Option<String> {
    std::thread::current().name().map(str::to_owned)
}

fn truncate_with_mark(value: &mut String, limit: usize) {
    if value.len() <= limit {
        return;
    }
    let mut end = limit.saturating_sub(TRUNCATION_MARK.len());
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    value.push_str(TRUNCATION_MARK);
}

/// Bounds `input` to `limit` bytes and replaces what may identify the user
/// or a server, or be a credential: double-quoted text, which is how `Debug`
/// prints strings such as a config value in an `unwrap` message, IP
/// addresses, URLs, user@host, domains, UUIDs and long key-like tokens.
/// Control characters other than newline and tab become spaces.
fn redact(input: &str, limit: usize) -> String {
    let mut out = String::with_capacity(input.len().min(limit));
    let mut rest = input;
    while let Some(ch) = rest.chars().next() {
        if out.len() > limit {
            break;
        }
        if ch == '"' {
            out.push_str("\"<redacted>\"");
            rest = skip_quoted(rest);
        } else if is_token_char(ch) {
            let end = rest
                .find(|ch: char| !is_token_char(ch))
                .unwrap_or(rest.len());
            out.push_str(redact_token(&rest[..end]));
            rest = &rest[end..];
        } else {
            out.push(if ch.is_control() && ch != '\n' && ch != '\t' {
                ' '
            } else {
                ch
            });
            rest = &rest[ch.len_utf8()..];
        }
    }
    truncate_with_mark(&mut out, limit);
    out
}

/// The rest of `input`, which starts with a double quote, after its closing
/// quote; `Debug` escapes a quote inside with a backslash. An unclosed quote
/// runs to the end.
fn skip_quoted(input: &str) -> &str {
    let mut escaped = false;
    for (index, ch) in input.char_indices().skip(1) {
        match ch {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '"' => return &input[index + 1..],
            _ => {}
        }
    }
    ""
}

fn is_token_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric()
        || matches!(
            ch,
            '.' | ':' | '-' | '_' | '+' | '/' | '=' | '%' | '@' | '[' | ']' | '~'
        )
}

fn redact_token(token: &str) -> &str {
    let trimmed = token.trim_matches(|ch: char| matches!(ch, '.' | ':' | '-' | '[' | ']'));
    if trimmed.is_empty() {
        return token;
    }
    if trimmed.contains("://") {
        "<redacted-url>"
    } else if trimmed.contains('@') {
        "<redacted>"
    } else if is_ip_like(token) || is_ip_like(trimmed) {
        "<redacted-ip>"
    } else if contains_uuid(trimmed) {
        "<redacted-uuid>"
    } else if is_key_like(trimmed) {
        "<redacted>"
    } else if is_domain_like(trimmed) {
        "<redacted-domain>"
    } else {
        token
    }
}

fn is_ip_like(token: &str) -> bool {
    token.parse::<IpAddr>().is_ok() || token.parse::<SocketAddr>().is_ok()
}

fn contains_uuid(token: &str) -> bool {
    const GROUPS: [usize; 5] = [8, 4, 4, 4, 12];
    let bytes = token.as_bytes();
    (0..bytes.len().saturating_sub(35)).any(|start| {
        let mut position = start;
        GROUPS.iter().enumerate().all(|(index, &len)| {
            if index > 0 {
                if bytes.get(position) != Some(&b'-') {
                    return false;
                }
                position += 1;
            }
            let group = bytes.get(position..position + len);
            position += len;
            group.is_some_and(|group| group.iter().all(u8::is_ascii_hexdigit))
        })
    })
}

/// A long run of letters mixed with digits, as keys, passwords, short IDs
/// and base64 or hex material are. Source paths are kept.
fn is_key_like(token: &str) -> bool {
    let alphanumeric = token.bytes().filter(u8::is_ascii_alphanumeric).count();
    alphanumeric >= 20
        && token.bytes().any(|byte| byte.is_ascii_digit())
        && token.bytes().any(|byte| byte.is_ascii_alphabetic())
        && !is_source_path(token)
}

fn is_source_path(token: &str) -> bool {
    [".rs", ".swift", ".kt", ".c", ".h", ".cpp"]
        .iter()
        .any(|extension| {
            token.match_indices(extension).any(|(index, _)| {
                matches!(
                    token.as_bytes().get(index + extension.len()),
                    None | Some(b':')
                )
            })
        })
}

fn is_domain_like(token: &str) -> bool {
    const FILE_EXTENSIONS: [&str; 16] = [
        "rs", "swift", "kt", "h", "c", "cpp", "json", "toml", "dat", "mmdb", "db", "log", "txt",
        "so", "dylib", "a",
    ];
    if token.contains('/') || !token.contains('.') {
        return false;
    }
    let mut labels = token.split('.');
    let Some(last) = labels.next_back() else {
        return false;
    };
    last.len() >= 2
        && last.bytes().all(|byte| byte.is_ascii_alphabetic())
        && !FILE_EXTENSIONS
            .iter()
            .any(|extension| last.eq_ignore_ascii_case(extension))
        && labels.all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

/// Return addresses of the current stack, one line per frame:
/// `index image+0xoffset [symbol+0xoffset]`. The image offset is what a
/// symbolicator such as `atos -l <load address>` takes; the symbol is the
/// nearest one the loader knows, which a stripped binary may not have.
#[inline(never)]
fn capture_backtrace() -> Option<String> {
    frames::capture()
}

#[cfg(all(
    any(target_vendor = "apple", target_os = "linux", target_os = "android"),
    not(target_arch = "arm")
))]
mod frames {
    use std::ffi::{c_int, c_void, CStr};
    use std::fmt::Write as _;

    use super::{
        MAX_BACKTRACE_BYTES, MAX_BACKTRACE_FRAMES, MAX_FRAME_LINE_BYTES, MAX_SYMBOL_BYTES,
    };

    /// `capture`, `capture_backtrace` and, from the hook, `record_panic`,
    /// all kept out of line.
    const OWN_FRAMES: usize = 3;
    const URC_NO_REASON: c_int = 0;
    const URC_END_OF_STACK: c_int = 5;

    #[repr(C)]
    struct UnwindContext {
        _opaque: [u8; 0],
    }

    type TraceFn = extern "C" fn(*mut UnwindContext, *mut c_void) -> c_int;

    // The unwinder every Rust binary with unwinding panics links already.
    unsafe extern "C" {
        fn _Unwind_Backtrace(trace: TraceFn, argument: *mut c_void) -> c_int;
        fn _Unwind_GetIP(context: *mut UnwindContext) -> usize;
    }

    struct Collector {
        addresses: [usize; MAX_BACKTRACE_FRAMES],
        len: usize,
        skip: usize,
    }

    extern "C" fn collect(context: *mut UnwindContext, argument: *mut c_void) -> c_int {
        // SAFETY: `argument` is the collector `capture` passed, alive for
        // the whole walk, and only this callback touches it meanwhile.
        let collector = unsafe { &mut *argument.cast::<Collector>() };
        // SAFETY: the unwinder passes a valid context for the frame.
        let address = unsafe { _Unwind_GetIP(context) };
        if address == 0 {
            return URC_END_OF_STACK;
        }
        if collector.skip > 0 {
            collector.skip -= 1;
            return URC_NO_REASON;
        }
        let Some(slot) = collector.addresses.get_mut(collector.len) else {
            return URC_END_OF_STACK;
        };
        *slot = address;
        collector.len += 1;
        if collector.len == collector.addresses.len() {
            URC_END_OF_STACK
        } else {
            URC_NO_REASON
        }
    }

    #[inline(never)]
    pub(super) fn capture() -> Option<String> {
        let mut collector = Collector {
            addresses: [0; MAX_BACKTRACE_FRAMES],
            len: 0,
            skip: OWN_FRAMES,
        };
        // SAFETY: `collect` matches the trace callback signature and only
        // reads the collector passed as its argument.
        unsafe {
            _Unwind_Backtrace(collect, std::ptr::from_mut(&mut collector).cast());
        }
        if collector.len == 0 {
            return None;
        }
        let mut text = [0u8; MAX_BACKTRACE_BYTES];
        let mut text_len = 0;
        for (index, &address) in collector.addresses[..collector.len].iter().enumerate() {
            let mut line = LineBuffer::default();
            // An overlong line keeps what fits, still ended by its newline.
            let _ = write_frame(&mut line, index, address);
            line.bytes[line.len] = b'\n';
            let line = &line.bytes[..=line.len];
            let Some(target) = text.get_mut(text_len..text_len + line.len()) else {
                break;
            };
            target.copy_from_slice(line);
            text_len += line.len();
        }
        Some(String::from_utf8_lossy(&text[..text_len]).into_owned())
    }

    fn write_frame(line: &mut LineBuffer, index: usize, address: usize) -> std::fmt::Result {
        // SAFETY: an all-zero Dl_info is a valid out-parameter.
        let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
        // SAFETY: dladdr only reads the address and fills `info`.
        let found = unsafe { libc::dladdr(address as *const c_void, &mut info) } != 0;
        if !found || info.dli_fbase.is_null() || info.dli_fname.is_null() {
            return write!(line, "{index:2} {address:#x}");
        }
        // SAFETY: dladdr succeeded, so dli_fname is a NUL-terminated path
        // owned by the loader.
        let path = unsafe { CStr::from_ptr(info.dli_fname) }.to_bytes();
        // Only the file name: the directory can name the app's container.
        let image = path.rsplit(|&byte| byte == b'/').next().unwrap_or(path);
        let image = std::str::from_utf8(image).unwrap_or("?");
        let offset = address.wrapping_sub(info.dli_fbase as usize);
        write!(line, "{index:2} {image}+{offset:#x}")?;
        if !info.dli_sname.is_null() && !info.dli_saddr.is_null() {
            // SAFETY: as above, a NUL-terminated name owned by the loader.
            let symbol = unsafe { CStr::from_ptr(info.dli_sname) }.to_bytes();
            let symbol = &symbol[..symbol.len().min(MAX_SYMBOL_BYTES)];
            let symbol = std::str::from_utf8(symbol).unwrap_or("?");
            let symbol_offset = address.wrapping_sub(info.dli_saddr as usize);
            write!(line, " {symbol}+{symbol_offset:#x}")?;
        }
        Ok(())
    }

    /// One frame's line, with room kept for its newline.
    struct LineBuffer {
        bytes: [u8; MAX_FRAME_LINE_BYTES],
        len: usize,
    }

    impl Default for LineBuffer {
        fn default() -> Self {
            Self {
                bytes: [0; MAX_FRAME_LINE_BYTES],
                len: 0,
            }
        }
    }

    impl std::fmt::Write for LineBuffer {
        fn write_str(&mut self, value: &str) -> std::fmt::Result {
            let room = self.bytes.len() - 1 - self.len;
            let mut take = value.len().min(room);
            while !value.is_char_boundary(take) {
                take -= 1;
            }
            self.bytes[self.len..self.len + take].copy_from_slice(&value.as_bytes()[..take]);
            self.len += take;
            if take < value.len() {
                return Err(std::fmt::Error);
            }
            Ok(())
        }
    }
}

#[cfg(not(all(
    any(target_vendor = "apple", target_os = "linux", target_os = "android"),
    not(target_arch = "arm")
)))]
mod frames {
    pub(super) fn capture() -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: CrashEventKind, message: &str) -> NewEvent {
        NewEvent {
            kind,
            message: message.to_owned(),
            location: None,
            thread: None,
            backtrace: None,
            count: 1,
        }
    }

    fn parse(json: &str) -> serde_json::Value {
        serde_json::from_str(json).expect("crash report is valid JSON")
    }

    fn messages(document: &serde_json::Value) -> Vec<String> {
        document["events"]
            .as_array()
            .expect("events array")
            .iter()
            .map(|event| event["message"].as_str().unwrap().to_owned())
            .collect()
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time should be after epoch")
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("temp dir should be created");
        dir
    }

    #[test]
    fn the_ring_keeps_the_newest_events_and_counts_the_dropped_ones() {
        let mut recorder = Recorder::new();
        for index in 0..MAX_EVENTS + 5 {
            assert!(recorder.push(
                event(CrashEventKind::TaskExit, &format!("event {index}")),
                7
            ));
        }

        assert_eq!(recorder.events.len(), MAX_EVENTS);
        let document = parse(&recorder.take_within(usize::MAX).unwrap());
        assert_eq!(document["schemaVersion"], 1);
        assert_eq!(document["droppedEvents"], 5);
        let messages = messages(&document);
        assert_eq!(messages.len(), MAX_EVENTS);
        assert_eq!(messages.first().unwrap(), "event 5");
        assert_eq!(
            messages.last().unwrap(),
            &format!("event {}", MAX_EVENTS + 4)
        );
    }

    #[test]
    fn a_repeated_event_is_counted_not_added_again() {
        let mut recorder = Recorder::new();
        assert!(recorder.push(event(CrashEventKind::Panic, "boom"), 10));
        assert!(!recorder.push(event(CrashEventKind::Panic, "boom"), 20));
        assert!(recorder.push(event(CrashEventKind::TaskPanic, "boom"), 30));

        let document = parse(&recorder.take_within(usize::MAX).unwrap());
        let events = document["events"].as_array().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["count"], 2);
        assert_eq!(events[0]["firstUnixMs"], 10);
        assert_eq!(events[0]["unixMs"], 20);
    }

    #[test]
    fn a_take_clears_what_it_returns_and_a_short_limit_takes_nothing() {
        let mut recorder = Recorder::new();
        recorder.push(event(CrashEventKind::Panic, "first"), 1);

        let required = recorder.take_within(10).unwrap_err();
        assert_eq!(required, recorder.pending_json().len());
        assert_eq!(messages(&parse(&recorder.pending_json())), ["first"]);

        let taken = recorder.take_within(required).unwrap();
        assert_eq!(messages(&parse(&taken)), ["first"]);
        assert!(messages(&parse(&recorder.pending_json())).is_empty());

        // A repeat after the take is a new event for the next take.
        recorder.push(event(CrashEventKind::Panic, "first"), 2);
        let document = parse(&recorder.take_within(usize::MAX).unwrap());
        assert_eq!(messages(&document), ["first"]);
        assert_eq!(document["events"][0]["count"], 1);
    }

    #[test]
    fn taken_events_leave_the_ring_first_without_counting_as_dropped() {
        let mut recorder = Recorder::new();
        recorder.push(event(CrashEventKind::Panic, "taken"), 1);
        recorder.take_within(usize::MAX).unwrap();
        for index in 0..MAX_EVENTS {
            recorder.push(event(CrashEventKind::TaskExit, &format!("new {index}")), 2);
        }

        let document = parse(&recorder.take_within(usize::MAX).unwrap());
        assert_eq!(document["droppedEvents"], 0);
        assert_eq!(messages(&document).len(), MAX_EVENTS);
        assert_eq!(recorder.evicted, 1);
    }

    #[test]
    fn json_strings_are_escaped() {
        let mut recorder = Recorder::new();
        recorder.push(
            NewEvent {
                backtrace: Some(" 0 image+0x10\n 1 image+0x20\n".to_owned()),
                location: Some("src/a.rs:1:2".to_owned()),
                thread: Some("worker \"1\"".to_owned()),
                ..event(
                    CrashEventKind::Panic,
                    "quote \" slash \\ tab \t bell \u{7} é",
                )
            },
            5,
        );

        let document = parse(&recorder.take_within(usize::MAX).unwrap());
        let event = &document["events"][0];
        assert_eq!(event["kind"], "panic");
        assert_eq!(event["message"], "quote \" slash \\ tab \t bell \u{7} é");
        assert_eq!(event["thread"], "worker \"1\"");
        assert_eq!(event["backtrace"], " 0 image+0x10\n 1 image+0x20\n");
        assert_eq!(event["location"], "src/a.rs:1:2");
    }

    #[test]
    fn the_report_file_mirrors_the_ring_and_keeps_the_previous_one() {
        let dir = unique_temp_dir("xray-crash-report");
        let mut recorder = Recorder::new();
        recorder.push(event(CrashEventKind::Panic, "before"), 1);
        recorder.set_directory(Some(&dir), 0).unwrap();
        let current = report_file_path(&dir);
        assert_eq!(
            messages(&parse(&fs::read_to_string(&current).unwrap())),
            ["before"]
        );

        // A new panic is written at once, whatever the interval.
        recorder.push(event(CrashEventKind::Panic, "after"), 2);
        recorder.persist(1, true);
        let document = parse(&fs::read_to_string(&current).unwrap());
        assert_eq!(messages(&document), ["before", "after"]);
        assert_eq!(document["pid"], std::process::id());

        // Other events wait out the interval, then the next take writes them.
        recorder.take_within(usize::MAX).unwrap();
        recorder.push(event(CrashEventKind::TaskExit, "later"), 3);
        recorder.persist(2, false);
        assert_eq!(
            messages(&parse(&fs::read_to_string(&current).unwrap())).len(),
            2
        );
        recorder.persist_if_dirty(3);
        // Taken events stay in the file.
        assert_eq!(
            messages(&parse(&fs::read_to_string(&current).unwrap())),
            ["before", "after", "later"]
        );

        // The same directory again does not move the report aside.
        recorder.set_directory(Some(&dir), 4).unwrap();
        assert!(!previous_report_file_path(&dir).exists());

        // A new process (a fresh recorder) moves it aside first.
        let mut next = Recorder::new();
        next.set_directory(Some(&dir), 0).unwrap();
        assert_eq!(
            messages(&parse(
                &fs::read_to_string(previous_report_file_path(&dir)).unwrap()
            )),
            ["before", "after", "later"]
        );
        assert!(messages(&parse(&fs::read_to_string(&current).unwrap())).is_empty());
        assert!(!dir.join(TEMPORARY_REPORT_FILE_NAME).exists());

        assert!(next.set_directory(Some(&dir.join("missing")), 0).is_err());
        assert!(next.file.is_none(), "an unusable directory is not kept");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_report_file_leaves_out_the_oldest_events_when_full() {
        let dir = unique_temp_dir("xray-crash-report-full");
        let mut recorder = Recorder::new();
        let backtrace = "x".repeat(MAX_BACKTRACE_BYTES);
        for index in 0..MAX_EVENTS {
            recorder.push(
                NewEvent {
                    backtrace: Some(backtrace.clone()),
                    ..event(CrashEventKind::Panic, &format!("panic {index}"))
                },
                1,
            );
        }
        recorder.set_directory(Some(&dir), 0).unwrap();

        let raw = fs::read_to_string(report_file_path(&dir)).unwrap();
        assert!(raw.len() <= MAX_REPORT_FILE_BYTES);
        let document = parse(&raw);
        let kept = messages(&document);
        assert!(!kept.is_empty() && kept.len() < MAX_EVENTS);
        assert_eq!(kept.last().unwrap(), &format!("panic {}", MAX_EVENTS - 1));
        assert_eq!(document["droppedEvents"], (MAX_EVENTS - kept.len()) as u64);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_summary_counter_adds_the_first_count_at_once_then_per_interval() {
        let counter = SummaryCounter::new(CrashEventKind::FlowBudgetExhausted, "budget");
        let mut recorder = Recorder::new();

        assert!(counter.count_one(100));
        assert!(counter.flush_into(&mut recorder, 1));
        assert!(!counter.count_one(200));
        assert!(!counter.count_one(100 + SUMMARY_INTERVAL_MS - 1));
        assert!(counter.count_one(100 + SUMMARY_INTERVAL_MS));
        assert!(counter.flush_into(&mut recorder, 2));
        assert!(!counter.flush_into(&mut recorder, 3), "nothing left to add");

        let document = parse(&recorder.take_within(usize::MAX).unwrap());
        assert_eq!(document["events"].as_array().unwrap().len(), 1);
        assert_eq!(document["events"][0]["kind"], "flowBudgetExhausted");
        assert_eq!(document["events"][0]["count"], 4);
    }

    #[test]
    fn messages_are_redacted_and_bounded() {
        let redacted = redact(
            "dial 203.0.113.7:443 [2001:db8::1]:8443 for edge.example.com \
             id 6ba7b810-9dad-11d1-80b4-00c04fd430c8 key c2VjcmV0LWtleS0xMjM0NTY3ODkw \
             url vless://user@host.test:443 index 5 of 3 in crates/xray-core-rs/src/tun.rs:12:5",
            MAX_MESSAGE_BYTES,
        );
        assert_eq!(
            redacted,
            "dial <redacted-ip> <redacted-ip> for <redacted-domain> \
             id <redacted-uuid> key <redacted> \
             url <redacted-url> index 5 of 3 in crates/xray-core-rs/src/tun.rs:12:5"
        );
        assert_eq!(
            redact("called `Option::unwrap()` on a `None` value", 100),
            "called `Option::unwrap()` on a `None` value"
        );
        assert_eq!(
            redact(
                r#"called `Result::unwrap()` on an `Err` value: Parse { input: "hunter2 \"x\"", at: 3 }"#,
                200
            ),
            r#"called `Result::unwrap()` on an `Err` value: Parse { input: "<redacted>", at: 3 }"#
        );
        assert_eq!(redact(r#"open "unterminated"#, 100), r#"open "<redacted>""#);
        assert_eq!(redact("line\nfeed\u{1b}[0m", 100), "line\nfeed [0m");

        let long = redact(&"word ".repeat(1000), MAX_MESSAGE_BYTES);
        assert_eq!(long.len(), MAX_MESSAGE_BYTES);
        assert!(long.ends_with(TRUNCATION_MARK));
    }

    #[test]
    fn dependency_locations_lose_the_registry_path() {
        #[track_caller]
        fn here() -> &'static Location<'static> {
            Location::caller()
        }
        assert!(format_location(here()).starts_with("crates/xray-core-rs/src/crash_report.rs:"));
    }

    #[cfg(all(
        any(target_vendor = "apple", target_os = "linux", target_os = "android"),
        not(target_arch = "arm")
    ))]
    #[test]
    fn a_backtrace_is_bounded_lines_of_image_offsets() {
        let backtrace = capture_backtrace().expect("this target walks its stack");
        let lines = backtrace.lines().collect::<Vec<_>>();
        assert!(!lines.is_empty() && lines.len() <= MAX_BACKTRACE_FRAMES);
        assert!(backtrace.len() <= MAX_BACKTRACE_BYTES);
        assert!(lines[0].starts_with(" 0 "));
        assert!(lines.iter().any(|line| line.contains("+0x")));
        assert!(!backtrace.contains('/'), "image directories are left out");
    }

    #[tokio::test]
    async fn a_panic_in_a_spawned_task_is_recorded_by_the_hook() {
        let _global = TEST_LOCK.lock().await;
        install_panic_hook();
        take_json();

        let joined = tokio::spawn(async {
            panic!("crash-report-hook-marker at 198.51.100.4");
        })
        .await;
        assert!(joined.unwrap_err().is_panic());

        let document = parse(&take_json());
        let event = document["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|event| {
                event["message"]
                    .as_str()
                    .unwrap()
                    .contains("crash-report-hook-marker")
            })
            .expect("the panic was recorded")
            .clone();
        assert_eq!(event["kind"], "panic");
        assert_eq!(
            event["message"],
            "crash-report-hook-marker at <redacted-ip>"
        );
        assert!(event["location"]
            .as_str()
            .unwrap()
            .starts_with("crates/xray-core-rs/src/crash_report.rs:"));
        assert!(event["thread"].is_string() || event["thread"].is_null());
        if frames::capture().is_some() {
            assert!(!event["backtrace"].as_str().unwrap().is_empty());
        }
        assert!(
            !take_json().contains("crash-report-hook-marker"),
            "take clears"
        );
    }

    #[tokio::test]
    async fn a_supervised_task_records_its_panic_and_an_early_return() {
        let _global = TEST_LOCK.lock().await;
        take_json();
        let (shutdown, receiver) = watch::channel(false);

        let joined = tokio::spawn(supervise_until_shutdown(
            "crash-report test loop",
            receiver.clone(),
            async { panic!("crash-report-task-marker") },
        ))
        .await;
        assert!(
            joined.unwrap_err().is_panic(),
            "the panic still reaches the join"
        );
        supervise_until_shutdown("crash-report early loop", receiver.clone(), async {}).await;
        shutdown.send(true).unwrap();
        supervise_until_shutdown("crash-report stopped loop", receiver, async {}).await;

        let document = parse(&take_json());
        let found = |kind: &str, message: &str| {
            document["events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|event| event["kind"] == kind && event["message"] == message)
        };
        assert!(found(
            "taskPanic",
            "crash-report test loop panicked: crash-report-task-marker"
        ));
        assert!(found(
            "taskExit",
            "crash-report early loop stopped before the core was stopped"
        ));
        assert!(!found(
            "taskExit",
            "crash-report stopped loop stopped before the core was stopped"
        ));
    }

    #[tokio::test]
    async fn a_critical_event_carries_its_callers_location() {
        let _global = TEST_LOCK.lock().await;
        take_json();
        record(CrashEventKind::TunFdReadExit, "crash-report-read-marker");

        let document = parse(&take_json());
        let event = document["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|event| event["message"] == "crash-report-read-marker")
            .expect("the event was recorded")
            .clone();
        assert_eq!(event["kind"], "tunFdReadExit");
        assert!(event["location"]
            .as_str()
            .unwrap()
            .starts_with("crates/xray-core-rs/src/crash_report.rs:"));
        assert!(event["backtrace"].is_null());
    }
}
