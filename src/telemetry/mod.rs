//! Anonymous, opt-in usage telemetry.
//!
//! Design constraints (see issue #1762):
//! - **Off by default.** Nothing is sent unless the user opts in via
//!   [`crate::session::TelemetryConfig::enabled`] in any settings surface.
//! - **`DO_NOT_TRACK` is absolute.** When set (`1` / `true` / `yes`), it
//!   suppresses both sending and install-id generation regardless of config.
//! - **Endpoint.** Opted-in sends go to the collection gateway at
//!   [`DEFAULT_ENDPOINT`] (which validates and re-sanitizes as a backstop);
//!   `AOE_TELEMETRY_ENDPOINT` overrides it, e.g. to point at a local sink. A
//!   compiled-in [`TELEMETRY_KEY`] is sent as `X-Telemetry-Key` so the gateway
//!   can shed drive-by noise (it is visible in source, so not real auth).
//! - **Fire-and-forget.** Sends run detached with a hard timeout (plus a short
//!   connect timeout so a down endpoint fails fast) and swallow every error
//!   (logged only at `debug`, `target: "telemetry"`). Telemetry must never
//!   slow, stall, or crash the tool.
//! - **Sanitized.** No content ever leaves [`sanitize`]: agent/model strings
//!   are coerced to a closed allowlist; raw commands, paths, titles, branch
//!   names, and prompts are never emitted.

pub mod events;
pub mod features;
pub mod sanitize;
mod state;

use std::collections::BTreeMap;
use std::time::Duration;

pub use events::{ProcessStart, Surface, UsageSnapshot, SCHEMA_VERSION};
pub use state::{claim_cli_process_start_slot, install_id, reset_install_id};

use crate::session::Instance;

/// Hard cap on any single telemetry send. Both the reqwest client timeout and
/// the outer flush bound use it, so a dead or slow endpoint can never delay
/// the CLI's exit or a daemon tick beyond this.
const SEND_TIMEOUT: Duration = Duration::from_secs(2);

/// Connect timeout for the send. Much shorter than [`SEND_TIMEOUT`] so a
/// black-holed or slow-DNS endpoint fails in well under a second rather than
/// costing a CLI run the full send budget.
const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);

/// Default collection gateway. Overridable via `AOE_TELEMETRY_ENDPOINT` (handy
/// for pointing at a local sink to inspect what is sent). The gateway
/// validates the envelope and re-sanitizes every field as a defense-in-depth
/// backstop. Nothing reaches it unless the user has opted in.
const DEFAULT_ENDPOINT: &str = "https://telemetry.agent-of-empires.com/v1/ingest";

/// Static key sent as `X-Telemetry-Key`. NOT authentication: it is visible in
/// this source, so it only lets the gateway drop unkeyed drive-by traffic. The
/// gateway must be configured to require this exact value.
const TELEMETRY_KEY: &str = "7bc5a4e45ce861662b9690a7105da988";

/// CLI `process_start` is the only unbounded event source (one per `aoe`
/// invocation), so it is throttled to at most once per install per day. That
/// still answers "did this install run the CLI today" without a POST per
/// command.
const CLI_PROCESS_START_MIN_GAP: Duration = Duration::from_secs(24 * 60 * 60);

/// True when `DO_NOT_TRACK` is set to an affirmative value. This is the
/// absolute override: it wins over `config.telemetry.enabled`.
pub fn do_not_track() -> bool {
    match std::env::var("DO_NOT_TRACK") {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            matches!(v.as_str(), "1" | "true" | "yes")
        }
        Err(_) => false,
    }
}

/// The send endpoint. `AOE_TELEMETRY_ENDPOINT` overrides when set to a
/// non-empty value; otherwise the compiled-in [`DEFAULT_ENDPOINT`] is used.
/// Always returns a target, so the opt-in gate (not a missing endpoint) is
/// what decides whether anything is sent.
pub fn endpoint() -> String {
    match std::env::var("AOE_TELEMETRY_ENDPOINT") {
        Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => DEFAULT_ENDPOINT.to_string(),
    }
}

/// Consent state, ignoring whether a backend is wired. True when the user has
/// opted in and `DO_NOT_TRACK` is not suppressing. Drives id generation and
/// whether events are built at all.
pub fn is_opted_in() -> bool {
    crate::session::get_telemetry_settings().enabled && !do_not_track()
}

/// Apply an opt-in/opt-out transition's side effect on the install id. The
/// caller is responsible for persisting `config.telemetry.enabled`; this only
/// manages `telemetry.json`. Enabling (when not suppressed) generates the id;
/// disabling deletes it. Centralised so every surface (CLI, TUI, web, consent
/// prompts) behaves identically.
pub fn apply_opt_in_change(enabled: bool) {
    if enabled {
        if !do_not_track() {
            let _ = state::ensure_install_id();
        }
    } else if let Err(e) = state::delete_install_id() {
        tracing::debug!(target: "telemetry", "failed to delete install id on opt-out: {e}");
    }
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Build a `process_start` event, or `None` when telemetry is not opted in
/// (or `DO_NOT_TRACK` suppresses id generation).
pub fn build_process_start(surface: Surface) -> Option<ProcessStart> {
    if !is_opted_in() {
        return None;
    }
    let install_id = state::ensure_install_id()?;
    Some(ProcessStart {
        schema: SCHEMA_VERSION,
        event: "process_start",
        install_id,
        sent_at: now_rfc3339(),
        surface,
        aoe_version: env!("CARGO_PKG_VERSION").to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
    })
}

/// Build a `usage_snapshot` from the current sessions, or `None` when not
/// opted in. All agent/model strings pass through [`sanitize`]; raw values
/// never reach the payload.
pub fn build_usage_snapshot(
    surface: Surface,
    instances: &[Instance],
    web_seen: bool,
    cockpit_seen: bool,
    session_creates_since_last_snapshot: u32,
) -> Option<UsageSnapshot> {
    if !is_opted_in() {
        return None;
    }
    let install_id = state::ensure_install_id()?;
    let features = features::active_features(&crate::session::Config::load_or_warn());

    let mut sessions_by_agent: BTreeMap<String, u32> = BTreeMap::new();
    let mut sessions_by_model_bucket: BTreeMap<String, u32> = BTreeMap::new();
    let (mut running, mut idle, mut error, mut cockpit, mut sandboxed, mut yolo) =
        (0u32, 0u32, 0u32, 0u32, 0u32, 0u32);

    for inst in instances {
        match inst.status {
            crate::session::Status::Running => running += 1,
            crate::session::Status::Idle => idle += 1,
            crate::session::Status::Error => error += 1,
            _ => {}
        }
        // Cockpit fields only exist in `serve` builds; treat them as absent
        // otherwise so the snapshot logic stays surface-agnostic.
        #[cfg(feature = "serve")]
        let is_cockpit = inst.cockpit_mode;
        #[cfg(not(feature = "serve"))]
        let is_cockpit = false;
        if is_cockpit {
            cockpit += 1;
        }
        if inst.sandbox_info.as_ref().is_some_and(|s| s.enabled) {
            sandboxed += 1;
        }
        if inst.yolo_mode {
            yolo += 1;
        }

        // Prefer the canonical detection name; fall back to the raw tool
        // string. Either way it is coerced to an allowlisted bucket.
        let agent_src = if inst.detect_as.trim().is_empty() {
            inst.tool.as_str()
        } else {
            inst.detect_as.as_str()
        };
        *sessions_by_agent
            .entry(sanitize::agent_bucket(agent_src))
            .or_insert(0) += 1;

        #[cfg(feature = "serve")]
        let model = inst.cockpit_model.as_deref();
        #[cfg(not(feature = "serve"))]
        let model: Option<&str> = None;
        let bucket = sanitize::model_bucket(model);
        *sessions_by_model_bucket
            .entry(bucket.to_string())
            .or_insert(0) += 1;
    }

    Some(UsageSnapshot {
        schema: SCHEMA_VERSION,
        event: "usage_snapshot",
        install_id,
        sent_at: now_rfc3339(),
        surface,
        aoe_version: env!("CARGO_PKG_VERSION").to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        session_total: instances.len() as u32,
        session_running: running,
        session_idle: idle,
        session_error: error,
        session_cockpit: cockpit,
        session_sandboxed: sandboxed,
        session_yolo: yolo,
        sessions_by_agent,
        sessions_by_model_bucket,
        features,
        web_seen,
        cockpit_seen,
        session_creates_since_last_snapshot,
    })
}

/// POST a serialized event to the endpoint. Every error is swallowed and
/// logged at `debug` only. Bounded by both a short connect timeout and the
/// overall [`SEND_TIMEOUT`] so a down endpoint can never delay the caller.
async fn post<T: serde::Serialize>(event: &T) {
    let endpoint = endpoint();
    let client = match reqwest::Client::builder()
        .user_agent(concat!("agent-of-empires/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(SEND_TIMEOUT)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(target: "telemetry", "failed to build client: {e}");
            return;
        }
    };
    match client
        .post(&endpoint)
        .header("X-Telemetry-Key", TELEMETRY_KEY)
        .json(event)
        .send()
        .await
    {
        Ok(resp) => tracing::debug!(target: "telemetry", status = %resp.status(), "telemetry sent"),
        Err(e) => tracing::debug!(target: "telemetry", "telemetry send failed: {e}"),
    }
}

/// Emit a `process_start` for a long-running surface (TUI / serve). Detached:
/// returns immediately and never blocks the caller.
pub fn spawn_process_start(surface: Surface) {
    if let Some(event) = build_process_start(surface) {
        tokio::spawn(async move { post(&event).await });
    }
}

/// Emit a `process_start`, awaiting delivery with a hard timeout so the event
/// has a chance to flush before the process exits. Bounded by the connect and
/// send timeouts, so a dead endpoint can never hang the caller; a no-op for the
/// common default-off (not opted in) case.
pub async fn flush_process_start(surface: Surface) {
    if let Some(event) = build_process_start(surface) {
        let _ = tokio::time::timeout(SEND_TIMEOUT, post(&event)).await;
    }
}

/// CLI entrypoint for `process_start`: same as [`flush_process_start`] for the
/// `cli` surface, but throttled to at most once per install per day so a user
/// scripting `aoe` in a loop can't flood the endpoint. The throttle stamp is
/// only claimed when opted in, so default-off users never touch disk.
pub async fn flush_cli_process_start() {
    if is_opted_in() && state::claim_cli_process_start_slot(CLI_PROCESS_START_MIN_GAP) {
        flush_process_start(Surface::Cli).await;
    }
}

/// Fingerprint of the last `usage_snapshot` whose send we initiated this
/// process. Lets [`flush_snapshot_if_changed`] drop a redundant exit snapshot
/// that would otherwise repeat the boot (or last periodic) snapshot verbatim
/// within seconds. Process-local on purpose: a fresh launch starts empty, which
/// is correct because `process_start` already carries the per-launch signal, so
/// the snapshot only needs to report state and identical state is not worth
/// re-sending back to back.
static LAST_SNAPSHOT_FP: std::sync::Mutex<Option<u64>> = std::sync::Mutex::new(None);

/// Content fingerprint of a snapshot, excluding the volatile `sent_at` stamp.
/// Everything else is included: `install_id` is stable per install, so two
/// snapshots with the same counts hash equal. Used only for in-process dedup,
/// never sent anywhere.
fn snapshot_fingerprint(snapshot: &UsageSnapshot) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut probe = snapshot.clone();
    probe.sent_at = String::new();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    serde_json::to_string(&probe)
        .unwrap_or_default()
        .hash(&mut hasher);
    hasher.finish()
}

/// Record that we just initiated a send for `snapshot`, so a later
/// [`flush_snapshot_if_changed`] can tell whether anything changed since.
fn record_snapshot_fp(snapshot: &UsageSnapshot) {
    if let Ok(mut last) = LAST_SNAPSHOT_FP.lock() {
        *last = Some(snapshot_fingerprint(snapshot));
    }
}

/// True (and records the new fingerprint) when `snapshot` differs from the last
/// one we initiated a send for this process; false when it is identical. A
/// poisoned lock fails open: sending is the safe default.
fn snapshot_is_new(snapshot: &UsageSnapshot) -> bool {
    let fp = snapshot_fingerprint(snapshot);
    match LAST_SNAPSHOT_FP.lock() {
        Ok(mut last) => {
            let is_new = *last != Some(fp);
            if is_new {
                *last = Some(fp);
            }
            is_new
        }
        Err(_) => true,
    }
}

/// Send a pre-built usage snapshot, detached. Caller builds via
/// [`build_usage_snapshot`] (returns `None` when not opted in). Records the
/// fingerprint so a redundant exit snapshot can be suppressed.
pub fn spawn_snapshot(snapshot: UsageSnapshot) {
    record_snapshot_fp(&snapshot);
    tokio::spawn(async move { post(&snapshot).await });
}

/// Send the best-effort snapshot on graceful exit, awaiting delivery with a
/// hard timeout so the final snapshot can flush without risking a hang, but
/// skipping the send when the snapshot is identical (ignoring `sent_at`) to the
/// last one already emitted this run. A boot (or periodic) snapshot followed by
/// a quit with unchanged session state would otherwise post the same counts
/// twice within seconds; a snapshot that actually changed still flushes.
pub async fn flush_snapshot_if_changed(snapshot: UsageSnapshot) {
    if !snapshot_is_new(&snapshot) {
        tracing::debug!(target: "telemetry", "exit snapshot unchanged since last emit; skipping duplicate");
        return;
    }
    let _ = tokio::time::timeout(SEND_TIMEOUT, post(&snapshot)).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    // `#[serial]` (the default global group) serializes these env-mutating
    // tests against every other telemetry test that reads `DO_NOT_TRACK` /
    // `AOE_TELEMETRY_ENDPOINT`, including the consent-dialog tests in another
    // module, so none of them race on the shared process env.
    #[test]
    #[serial]
    fn do_not_track_recognises_affirmative_values() {
        for v in ["1", "true", "TRUE", "yes", "Yes"] {
            unsafe { std::env::set_var("DO_NOT_TRACK", v) };
            assert!(do_not_track(), "{v} should suppress");
        }
        for v in ["0", "false", "no", ""] {
            unsafe { std::env::set_var("DO_NOT_TRACK", v) };
            assert!(!do_not_track(), "{v} should not suppress");
        }
        unsafe { std::env::remove_var("DO_NOT_TRACK") };
        assert!(!do_not_track());
    }

    #[test]
    #[serial]
    fn endpoint_falls_back_to_default_and_env_overrides() {
        // Unset or blank => the compiled-in default gateway.
        unsafe { std::env::remove_var("AOE_TELEMETRY_ENDPOINT") };
        assert_eq!(endpoint(), DEFAULT_ENDPOINT);
        unsafe { std::env::set_var("AOE_TELEMETRY_ENDPOINT", "   ") };
        assert_eq!(endpoint(), DEFAULT_ENDPOINT);
        // A non-empty value overrides (trimmed).
        unsafe { std::env::set_var("AOE_TELEMETRY_ENDPOINT", " https://x/y ") };
        assert_eq!(endpoint(), "https://x/y");
        unsafe { std::env::remove_var("AOE_TELEMETRY_ENDPOINT") };
    }

    fn sample_snapshot() -> UsageSnapshot {
        UsageSnapshot {
            schema: SCHEMA_VERSION,
            event: "usage_snapshot",
            install_id: "00000000-0000-0000-0000-000000000000".to_string(),
            sent_at: "2026-06-02T19:00:45Z".to_string(),
            surface: Surface::Tui,
            aoe_version: "0.0.0".to_string(),
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            session_total: 7,
            session_running: 1,
            session_idle: 6,
            session_error: 0,
            session_cockpit: 0,
            session_sandboxed: 2,
            session_yolo: 0,
            sessions_by_agent: BTreeMap::new(),
            sessions_by_model_bucket: BTreeMap::new(),
            features: BTreeMap::new(),
            web_seen: false,
            cockpit_seen: false,
            session_creates_since_last_snapshot: 0,
        }
    }

    // Regression for the duplicate `usage_snapshot` seen in dogfooding: the TUI
    // (and serve) emit a snapshot at boot and another on graceful exit, so a
    // launch-then-quit with unchanged sessions posted the identical payload
    // twice within seconds. The exit path now dedups against the last emit.
    #[test]
    #[serial]
    fn exit_snapshot_dedups_against_boot_but_resends_on_change() {
        *LAST_SNAPSHOT_FP.lock().unwrap() = None;

        // Boot emit records the fingerprint (this is what spawn_snapshot does).
        let boot = sample_snapshot();
        record_snapshot_fp(&boot);

        // Quit right after, sessions unchanged: same content, newer stamp.
        // The only difference is `sent_at`, which the fingerprint excludes, so
        // the exit snapshot is recognised as a duplicate and not re-sent.
        let mut exit = sample_snapshot();
        exit.sent_at = "2026-06-02T19:00:47Z".to_string();
        assert!(
            !snapshot_is_new(&exit),
            "an unchanged exit snapshot must dedupe against the boot snapshot"
        );

        // A snapshot whose counts actually changed is new and would be sent,
        // and then becomes the new baseline.
        let mut changed = sample_snapshot();
        changed.session_total = 8;
        assert!(
            snapshot_is_new(&changed),
            "a changed snapshot must still be emitted"
        );
        let mut changed_again = changed.clone();
        changed_again.sent_at = "2026-06-02T19:05:00Z".to_string();
        assert!(
            !snapshot_is_new(&changed_again),
            "repeating the latest snapshot dedups against it"
        );

        *LAST_SNAPSHOT_FP.lock().unwrap() = None;
    }
}
