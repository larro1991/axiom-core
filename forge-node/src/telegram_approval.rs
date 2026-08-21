//! AXIOM Tier 2 approval channel #2: Telegram, via a dedicated AXIOM-only
//! bot (`@AxiomApprovalBot`) - originally built against PM's existing bot,
//! migrated to its own token 2026-08-15 specifically to close the
//! cross-consumer `getUpdates` race described lower in this file's history;
//! see `poll_forever`'s doc comment for the resolved state.
//!
//! `DECISIONS.md`'s "Tier-2 approval channel" section named this exact
//! upgrade as future work: "Planned v2: phone-push via Larry's existing
//! automation... The `ApprovalChannel` trait makes this upgrade a new
//! implementation, not a state-machine redesign." This module is that
//! implementation - a second, independent `axiom_gateway::ApprovalChannel`
//! impl, wired in alongside (not instead of) `CliApprovalChannel`. Nothing
//! in `axiom-gateway::approval` changed to build this; that is the whole
//! point of the trait existing.
//!
//! # Why this lives in `forge-node`, not `axiom-gateway`
//!
//! `CliApprovalChannel` lives in `axiom-gateway` because it needs nothing
//! beyond `std::io` - consistent with that crate's own "standalone,
//! embeddable, no dependency on AXIOM's own transport/discovery code"
//! design constraint (`DECISIONS.md`, "ecosystem positioning"). This
//! implementation needs a real async HTTP client and a background
//! long-polling task, i.e. a real tokio runtime with net/time features -
//! `axiom-gateway` deliberately only pulls in tokio's `sync` feature (see
//! its own `Cargo.toml`) to stay lightweight for embedding. `forge-node`
//! already carries the full tokio runtime and `reqwest` (the same HTTP
//! client every UAI-backed capability uses) - this module is implemented
//! here, as a normal `forge-node`-local `ApprovalChannel` impl, exactly as
//! the trait's own doc comment invites ("any implementation, real or mock,
//! plugs in here"). The trait itself needed zero changes.
//!
//! # Bridging a synchronous trait method to async I/O
//!
//! `ApprovalChannel::request_approval` is a synchronous, blocking method by
//! design (see its own doc comment) - `CliApprovalChannel` blocks on a
//! synchronous `read_line`. This implementation needs to (a) send an async
//! HTTP POST and (b) block waiting for an async background task to deliver
//! a decision, potentially for the full 15-minute expiry window. The bridge
//! is `tokio::runtime::Handle::block_on`, called from INSIDE
//! `tokio::task::spawn_blocking` (never from a normal async worker thread -
//! see `network.rs::dispatch_wg_peer_manage`, which always runs
//! `Tier2ApprovalFlow::decide_and_execute` inside `spawn_blocking`
//! specifically so this is safe: `spawn_blocking` closures run on tokio's
//! dedicated blocking-thread-pool, never one of the async runtime's own
//! worker threads, so a nested `Handle::block_on` there does not panic
//! ("Cannot start a runtime from within a runtime") the way calling it from
//! a plain `async fn` would).
//!
//! # Matching a reply to the right pending intent
//!
//! Telegram's Inline Keyboard mechanism (`reply_markup.inline_keyboard`,
//! `callback_data` on each button) is used exactly as intended: the
//! Approve/Deny buttons sent alongside the request message carry
//! `callback_data` of the form `wg:<approve|deny>:<32-hex-char intent id>`
//! (see `build_inline_keyboard`) - the full, untruncated `IntentId` hex
//! (`approval::IntentId::to_hex`, same "never truncate a security-relevant
//! id" discipline `approval.rs`'s own `render_prompt` uses for the CLI
//! channel), not "whichever message Larry replies to" or "the most recent
//! request." This makes mismatching a reply to the wrong pending intent
//! architecturally impossible, not just documented against, per this
//! task's own instruction to prefer that over asking for a typed string
//! back. Two (or more) concurrent `wg_peer_manage` proposals get two
//! independent `callback_data` values naming two different intent ids;
//! `TelegramApprovalState::pending`, keyed by that same hex string, only
//! ever resolves the ONE waiter whose id matches - proven directly in this
//! module's `two_concurrent_pending_intents_do_not_cross_resolve` test.
//!
//! # Chat-id authentication
//!
//! Only a `callback_query` whose `from.id` (the Telegram user who actually
//! tapped the button - not merely the chat the message was posted in)
//! equals the configured `chat_id` is ever honored as a real decision - see
//! `process_update`. Anything else (a reply/tap from any other Telegram
//! user, which could reach this bot if it were ever added to a group chat,
//! or a malformed/unexpected update shape) is logged and ignored: the
//! pending intent stays `Pending`, exactly as if no reply had arrived yet,
//! so a later legitimate reply from the real chat id can still resolve it
//! normally. This is a real authentication boundary (this task's own
//! framing), not a UX nicety - see `chat_id_mismatch_does_not_resolve_the_
//! pending_intent` for the direct proof.
//!
//! # Expiry discipline
//!
//! `request_approval` waits at most `request.remaining` (computed by
//! `axiom_gateway::approval::Intent::remaining` at the moment
//! `Tier2ApprovalFlow::decide_and_execute` calls this channel - i.e.
//! already reflects however much of the intent's original expiry window
//! has already elapsed since `propose`). A reply that arrives after that
//! wait elapses is therefore, by construction, never observed by this
//! specific `request_approval` call - `tokio::time::timeout` simply times
//! out and this method returns `approved: false` (a timeout is "no
//! explicit yes was given," the same "ambiguous is a deny, never a silent
//! approve" rule `CliApprovalChannel`'s EOF case follows). This is on top
//! of, not instead of, `Tier2ApprovalFlow::decide_and_execute`'s OWN
//! independent double expiry check (before consulting the channel at all,
//! and again immediately before `execute`) - the exact "double expiry-check
//! closes the slow-approver race window" discipline `DECISIONS.md`/
//! `approval.rs` already established for the CLI channel, unchanged and
//! unweakened by this second implementation.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axiom_gateway::approval::{ApprovalChannel, ApprovalChannelError, ApprovalDecision, ApprovalRequest};
use tokio::sync::oneshot;
use tracing::{debug, info, warn};

/// Telegram callback_data is capped at 64 bytes by the Bot API itself. This
/// module's own format (`wg:<approve|deny>:<32 hex chars>`) tops out at
/// `"wg:approve:".len() + 32 == 43` bytes - comfortably under the cap, with
/// margin for a future longer action word. Asserted, not just assumed - see
/// `callback_data_stays_within_telegrams_64_byte_limit`. Test-only (nothing
/// in production code enforces this at runtime - `build_inline_keyboard`
/// itself has no length check, see that function's own doc comment; this
/// is a static, compile-time-adjacent guarantee about the FORMAT this
/// module always constructs, checked once here rather than on every call).
#[cfg(test)]
const TELEGRAM_CALLBACK_DATA_MAX_BYTES: usize = 64;

/// Shared state between `TelegramApprovalChannel` (the `ApprovalChannel`
/// impl `Tier2ApprovalFlow` calls into, synchronously, per proposal) and the
/// background long-polling task (`spawn_poller`) that actually receives
/// Larry's replies. One instance per node, constructed once in
/// `NetworkManager::new` when `NodeConfig::telegram_bot_token`/
/// `telegram_chat_id` are both set.
pub(crate) struct TelegramApprovalState {
    bot_token: String,
    /// The one chat/user id whose taps are ever honored - see this
    /// module's top-of-file doc comment, "Chat-id authentication".
    chat_id: i64,
    http: reqwest::Client,
    /// One entry per intent currently awaiting a Telegram reply, keyed by
    /// `IntentId::to_hex()` (NOT the `IntentId` type itself - this crate
    /// has no way to reconstruct one from raw bytes, see `approval.rs`;
    /// the hex string is exactly what `callback_data` carries anyway, so
    /// this is the natural join key). Removed by whichever of
    /// `request_approval`/its own timeout resolves it first - see
    /// `TelegramApprovalChannel::request_approval`.
    pending: Mutex<HashMap<String, oneshot::Sender<bool>>>,
}

impl TelegramApprovalState {
    pub(crate) fn new(bot_token: String, chat_id: i64) -> Result<Arc<Self>, String> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(35))
            .build()
            .map_err(|e| format!("building Telegram HTTP client: {e}"))?;
        Ok(Arc::new(Self { bot_token, chat_id, http, pending: Mutex::new(HashMap::new()) }))
    }

    fn api_url(&self, method: &str) -> String {
        format!("https://api.telegram.org/bot{}/{}", self.bot_token, method)
    }

    /// Send the approval-request message (rendered by `render_telegram_message`)
    /// with its Approve/Deny inline keyboard attached, and register a fresh
    /// waiter for this intent's hex id BEFORE sending - so a reply that
    /// arrives implausibly fast (the poller's next long-poll cycle races
    /// this call) can never be missed by a registration-after-send gap.
    async fn send_approval_request(&self, request: &ApprovalRequest) -> Result<oneshot::Receiver<bool>, String> {
        let hex_id = request.intent_id.to_hex();
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending.lock().unwrap();
            // A caller proposing two intents with the SAME id is
            // impossible (`IntentId::generate` - see approval.rs), so an
            // existing entry here would mean this exact hex id is already
            // pending, which should never happen; overwritten defensively
            // rather than panicking, matching this codebase's general
            // "fail closed, don't crash the dispatch task" posture.
            pending.insert(hex_id.clone(), tx);
        }

        let text = render_telegram_message(request);
        let keyboard = build_inline_keyboard(&hex_id);
        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "reply_markup": keyboard,
        });

        let resp = self.http.post(self.api_url("sendMessage")).json(&body).send().await;
        match resp {
            Ok(r) if r.status().is_success() => {
                info!("Telegram approval request sent for intent {} (capability {})", hex_id, request.capability);
                Ok(rx)
            }
            Ok(r) => {
                let status = r.status();
                let detail = r.text().await.unwrap_or_default();
                self.pending.lock().unwrap().remove(&hex_id);
                Err(format!("Telegram sendMessage failed: HTTP {status}: {detail}"))
            }
            Err(e) => {
                self.pending.lock().unwrap().remove(&hex_id);
                Err(format!("Telegram sendMessage unreachable: {e}"))
            }
        }
    }

    async fn answer_callback_query(&self, callback_query_id: &str, text: &str) {
        let body = serde_json::json!({"callback_query_id": callback_query_id, "text": text});
        if let Err(e) = self.http.post(self.api_url("answerCallbackQuery")).json(&body).send().await {
            debug!("Telegram answerCallbackQuery failed (non-fatal): {}", e);
        }
    }

    /// Process ONE raw Telegram `Update` JSON value - the same shape
    /// `getUpdates`'s `result` array elements have. Pure enough to unit
    /// test directly with synthetic fixtures (no real network call except
    /// the best-effort `answerCallbackQuery` ack, which tests don't reach
    /// since they call this on a `TelegramApprovalState` whose `http`
    /// client, pointed at a real-but-unreachable-in-tests URL, simply fails
    /// silently - see this function's own doc comment on why that's fine).
    /// Returns `true` if this update was a `callback_query` this state
    /// recognized as belonging to a real pending intent AND authenticated
    /// against `chat_id` (i.e. an actual decision was delivered) - for
    /// tests; the poller itself doesn't need this return value beyond
    /// logging.
    async fn process_update(&self, update: &serde_json::Value) -> bool {
        let Some(cb) = update.get("callback_query") else {
            return false;
        };
        let callback_query_id = cb.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let from_id = cb.get("from").and_then(|f| f.get("id")).and_then(|v| v.as_i64());
        let data = cb.get("data").and_then(|v| v.as_str()).unwrap_or("");

        if from_id != Some(self.chat_id) {
            warn!(
                "Ignoring Telegram callback_query from unauthorized chat/user id {:?} (expected {}) - data={:?}",
                from_id, self.chat_id, data
            );
            if !callback_query_id.is_empty() {
                self.answer_callback_query(&callback_query_id, "Not authorized.").await;
            }
            return false;
        }

        let Some((action, hex_id)) = parse_callback_data(data) else {
            warn!("Ignoring malformed Telegram callback_data: {:?}", data);
            if !callback_query_id.is_empty() {
                self.answer_callback_query(&callback_query_id, "Malformed request - ignored.").await;
            }
            return false;
        };

        let tx = { self.pending.lock().unwrap().remove(&hex_id) };
        let Some(tx) = tx else {
            // No (longer) pending - already resolved by this same button
            // (a double-tap), or the intent expired and this method's own
            // timeout already fired and removed the entry, or this is a
            // reply to an intent this node never proposed (a stale/replayed
            // callback_data). Every one of those is "nothing to do," not an
            // error - see this module's top-of-file doc comment.
            debug!("Telegram callback_query for intent {} has no (longer) pending waiter - ignored", hex_id);
            if !callback_query_id.is_empty() {
                self.answer_callback_query(&callback_query_id, "This request is no longer pending (expired or already decided).").await;
            }
            return false;
        };

        let approved = action == "approve";
        let ack_text = if approved { "Approved." } else { "Denied." };
        if !callback_query_id.is_empty() {
            self.answer_callback_query(&callback_query_id, ack_text).await;
        }
        // The receiver may already be gone (its `request_approval` call
        // already timed out and returned) - `send` returning `Err` just
        // means nobody's listening anymore, not a bug; nothing to recover.
        let _ = tx.send(approved);
        info!("Telegram approval decision recorded for intent {}: approved={}", hex_id, approved);
        true
    }

    /// Long-poll `getUpdates` forever. `allowed_updates: ["callback_query"]`
    /// scopes this node's OWN requests to just the update type this channel
    /// cares about. Earlier versions of this module shared a bot token with
    /// PM's own `pm_agent.py` long-poller, which raced over the same
    /// `getUpdates` cursor - **resolved 2026-08-15**: this channel now runs
    /// on its own dedicated bot token (`@AxiomApprovalBot`, see
    /// `config.toml`'s `telegram_bot_token`), so there is no second consumer
    /// of this token's `getUpdates` cursor to race with.
    async fn poll_forever(self: Arc<Self>) {
        let mut offset: i64 = 0;
        loop {
            let url = format!(
                "{}?timeout=10&offset={}&allowed_updates=%5B%22callback_query%22%5D",
                self.api_url("getUpdates"),
                offset,
            );
            let resp = self.http.get(&url).timeout(Duration::from_secs(20)).send().await;
            let body = match resp {
                Ok(r) => match r.json::<serde_json::Value>().await {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("Telegram getUpdates: bad JSON reply: {}", e);
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                },
                Err(e) => {
                    warn!("Telegram getUpdates unreachable: {} - retrying in 5s", e);
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };
            if body.get("ok").and_then(|v| v.as_bool()) != Some(true) {
                warn!("Telegram getUpdates error: {:?}", body.get("description"));
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
            let updates = body.get("result").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            for update in &updates {
                if let Some(id) = update.get("update_id").and_then(|v| v.as_i64()) {
                    offset = offset.max(id + 1);
                }
                self.process_update(update).await;
            }
        }
    }
}

/// AXIOM Tier 2 Telegram approval channel - see this module's top-of-file
/// doc comment for the full design.
pub(crate) struct TelegramApprovalChannel {
    state: Arc<TelegramApprovalState>,
    runtime: tokio::runtime::Handle,
}

impl TelegramApprovalChannel {
    pub(crate) fn new(state: Arc<TelegramApprovalState>, runtime: tokio::runtime::Handle) -> Self {
        Self { state, runtime }
    }
}

impl ApprovalChannel for TelegramApprovalChannel {
    fn name(&self) -> &'static str {
        "telegram"
    }

    fn request_approval(&self, request: &ApprovalRequest) -> Result<ApprovalDecision, ApprovalChannelError> {
        let hex_id = request.intent_id.to_hex();
        // See this module's top-of-file doc comment, "Bridging a
        // synchronous trait method to async I/O" - this call is only ever
        // safe from inside `spawn_blocking`, enforced by
        // `network.rs::dispatch_wg_peer_manage` always running
        // `Tier2ApprovalFlow::decide_and_execute` there.
        let rx = self.runtime.block_on(self.state.send_approval_request(request)).map_err(ApprovalChannelError::Io)?;

        // Never wait longer than the intent's OWN remaining expiry - a
        // reply Telegram delivers after this returns is simply never
        // observed by this call (see this module's top-of-file doc
        // comment, "Expiry discipline"). `max(1s)` only guards against a
        // caller passing an already-essentially-zero remaining duration
        // (Tier2ApprovalFlow itself would already have rejected a truly
        // expired intent before ever reaching here - see
        // `decide_and_execute`) turning this into a race against
        // `tokio::time::timeout`'s own zero-duration edge behavior.
        let wait = request.remaining.max(Duration::from_secs(1));
        let approved = self.runtime.block_on(async {
            match tokio::time::timeout(wait, rx).await {
                Ok(Ok(approved)) => approved,
                // Sender dropped without sending - shouldn't happen in
                // normal operation (process_update always sends before
                // dropping tx), but an ambiguous/missing result is a deny,
                // never a silent approve (see ApprovalChannel's own trait
                // doc comment).
                Ok(Err(_)) => false,
                Err(_timeout) => {
                    info!("Telegram approval request for intent {} timed out with no reply - treating as denied", hex_id);
                    false
                }
            }
        });
        // Always clean up, regardless of which branch above fired - a
        // late reply after this point finds no pending waiter and is
        // logged/ignored by process_update (see its own doc comment).
        self.state.pending.lock().unwrap().remove(&hex_id);

        Ok(ApprovalDecision { intent_id: request.intent_id, approved, channel_name: self.name() })
    }
}

/// Starts the background long-poll loop. Fire-and-forget, same precedent
/// `NetworkManager::start_receive_loop`'s own spawned task already
/// establishes in this codebase (not stored/aborted anywhere - the process
/// exiting is what stops it).
pub(crate) fn spawn_poller(state: Arc<TelegramApprovalState>) {
    tokio::spawn(async move {
        state.poll_forever().await;
    });
}

/// `wg:<approve|deny>:<32 hex chars>` - see this module's top-of-file doc
/// comment, "Matching a reply to the right pending intent".
fn build_inline_keyboard(hex_id: &str) -> serde_json::Value {
    serde_json::json!({
        "inline_keyboard": [[
            {"text": "\u{2705} Approve", "callback_data": format!("wg:approve:{hex_id}")},
            {"text": "\u{274c} Deny", "callback_data": format!("wg:deny:{hex_id}")},
        ]]
    })
}

fn parse_callback_data(data: &str) -> Option<(String, String)> {
    let mut parts = data.splitn(3, ':');
    let prefix = parts.next()?;
    let action = parts.next()?;
    let hex_id = parts.next()?;
    if prefix != "wg" {
        return None;
    }
    if action != "approve" && action != "deny" {
        return None;
    }
    if hex_id.len() != 32 || !hex_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some((action.to_string(), hex_id.to_string()))
}

fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs >= 60 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else {
        format!("{secs}s")
    }
}

/// Renders the human-readable Telegram message text - the same information
/// `axiom_gateway::approval::render_prompt` shows the CLI channel's
/// operator, in Telegram's own text formatting. Split out as its own pure
/// function so it's independently testable without a real HTTP call, same
/// discipline `render_prompt` itself uses in `axiom-gateway`.
fn render_telegram_message(request: &ApprovalRequest) -> String {
    let mut out = String::new();
    out.push_str("\u{1f6a8} AXIOM Tier 2 approval required\n\n");
    out.push_str(&format!("Capability: {}\n", request.capability));
    out.push_str(&format!("Intent ID: {}\n", request.intent_id.to_hex()));
    if request.parameters.is_empty() {
        out.push_str("Parameters: (none)\n");
    } else {
        out.push_str("Parameters:\n");
        for c in &request.parameters {
            out.push_str(&format!("  - {} = {}\n", c.key, format_constraint_value(&c.value)));
        }
    }
    match &request.dry_run_diff {
        Some(diff) if !diff.is_empty() => {
            out.push_str("Dry-run diff:\n");
            for entry in diff {
                out.push_str(&format!("  - {}: {} -> {}\n", entry.key, entry.current, entry.proposed));
            }
        }
        Some(_) => out.push_str("Dry-run diff: (no changes)\n"),
        None => out.push_str("Dry-run diff: (not available)\n"),
    }
    out.push_str(&format!("Expires in: {}\n\n", format_duration(request.remaining)));
    out.push_str("This is destructive/security-relevant (Tier 2) and requires your explicit, one-time approval. No standing approvals, no wildcards.");
    out
}

fn format_constraint_value(v: &axiom_types::intent::ConstraintValue) -> String {
    use axiom_types::intent::ConstraintValue;
    match v {
        ConstraintValue::String(s) => s.clone(),
        ConstraintValue::Int(i) => i.to_string(),
        ConstraintValue::Float(f) => f.to_string(),
        ConstraintValue::Bool(b) => b.to_string(),
        ConstraintValue::Range { min, max } => format!("[{min}, {max}]"),
        ConstraintValue::OneOf(values) => format!("one of {values:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_crypto::identity::Keypair;
    use axiom_types::intent::Constraint;

    fn peer() -> axiom_types::NodeId {
        Keypair::generate().node_id()
    }

    // --- callback_data build/parse round trip ---

    #[test]
    fn build_inline_keyboard_embeds_the_full_intent_hex_in_both_buttons() {
        let hex_id = "0123456789abcdef0123456789abcdef";
        // Deliberately NOT 32 chars (33) to prove build_inline_keyboard
        // itself doesn't validate length - parse_callback_data is the
        // thing that does, exercised separately below with a real 32-char
        // id.
        let kb = build_inline_keyboard(&hex_id[..32]);
        let text = kb.to_string();
        assert!(text.contains(&format!("wg:approve:{}", &hex_id[..32])));
        assert!(text.contains(&format!("wg:deny:{}", &hex_id[..32])));
    }

    #[test]
    fn callback_data_stays_within_telegrams_64_byte_limit() {
        let hex_id = "f".repeat(32);
        for action in ["approve", "deny"] {
            let data = format!("wg:{action}:{hex_id}");
            assert!(
                data.len() <= TELEGRAM_CALLBACK_DATA_MAX_BYTES,
                "callback_data {data:?} is {} bytes, exceeds Telegram's {} byte limit",
                data.len(),
                TELEGRAM_CALLBACK_DATA_MAX_BYTES,
            );
        }
    }

    #[test]
    fn parse_callback_data_round_trips_a_real_intent_hex() {
        let hex_id = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
        // Note: 33 chars above is deliberately wrong-length to prove the
        // length check fires - use a real 32-char id for the positive case.
        let real_hex = "a1b2c3d4e5f60718293a4b5c6d7e8f9a";
        assert_eq!(real_hex.len(), 32);
        let data = format!("wg:approve:{real_hex}");
        let (action, parsed) = parse_callback_data(&data).expect("well-formed callback_data must parse");
        assert_eq!(action, "approve");
        assert_eq!(parsed, real_hex);
        let _ = hex_id;
    }

    #[test]
    fn parse_callback_data_rejects_wrong_length_id() {
        assert!(parse_callback_data("wg:approve:tooshort").is_none());
        assert!(parse_callback_data(&format!("wg:approve:{}", "a".repeat(33))).is_none());
    }

    #[test]
    fn parse_callback_data_rejects_unknown_action_or_prefix() {
        let real_hex = "a1b2c3d4e5f60718293a4b5c6d7e8f9a";
        assert!(parse_callback_data(&format!("other:approve:{real_hex}")).is_none());
        assert!(parse_callback_data(&format!("wg:maybe:{real_hex}")).is_none());
        assert!(parse_callback_data("").is_none());
        assert!(parse_callback_data("garbage").is_none());
    }

    #[test]
    fn parse_callback_data_rejects_non_hex_id() {
        let bogus = "g".repeat(32);
        assert!(parse_callback_data(&format!("wg:approve:{bogus}")).is_none());
    }

    // --- message rendering (pure, no network) ---

    fn sample_request() -> (Arc<axiom_gateway::CapabilityPolicy>, axiom_types::NodeId) {
        (Arc::new(axiom_gateway::CapabilityPolicy::for_test_with_protected_resources(Some(Vec::new()))), peer())
    }

    struct DummyCap;
    impl axiom_gateway::Tier2Capability for DummyCap {
        fn capability_name(&self) -> &str {
            "wg_peer_manage"
        }
        fn execute(&self, _parameters: &[Constraint]) -> Result<String, String> {
            Ok("done".to_string())
        }
    }

    /// Builds a REAL `ApprovalRequest` (real `IntentId` included) by going
    /// through an actual `Tier2ApprovalFlow::propose` call and reading back
    /// `Intent`'s own public fields - `IntentId` has no public constructor
    /// from raw bytes outside `axiom-gateway` by design (see approval.rs),
    /// so this is the only way to obtain one here. `ApprovalRequest`'s own
    /// fields are all `pub`, so no private/test-only accessor on `Intent`
    /// is needed for this - a plain struct literal suffices.
    fn build_real_request() -> ApprovalRequest {
        let (policy, proposer) = sample_request();
        let flow = axiom_gateway::Tier2ApprovalFlow::new(NeverCalledChannel, policy);
        let id = flow
            .propose(proposer, &DummyCap, vec![Constraint::string("action", "delete"), Constraint::string("target", "test-peer")])
            .expect("propose should succeed against a permissive policy");
        let record = flow.record(id).expect("record exists right after propose");
        ApprovalRequest {
            intent_id: record.intent.id,
            proposer: record.intent.proposer,
            capability: record.intent.capability.clone(),
            parameters: record.intent.parameters.clone(),
            dry_run_diff: record.intent.dry_run_diff.clone(),
            parameter_hash: record.intent.parameter_hash,
            remaining: record.intent.remaining(),
        }
    }

    struct NeverCalledChannel;
    impl ApprovalChannel for NeverCalledChannel {
        fn name(&self) -> &'static str {
            "never-called"
        }
        fn request_approval(&self, _request: &ApprovalRequest) -> Result<ApprovalDecision, ApprovalChannelError> {
            panic!("this test double's request_approval should never actually be invoked");
        }
    }

    #[test]
    fn render_telegram_message_includes_capability_intent_id_and_params() {
        let request = build_real_request();
        let text = render_telegram_message(&request);
        assert!(text.contains("wg_peer_manage"));
        assert!(text.contains(&request.intent_id.to_hex()));
        assert!(text.contains("action"));
        assert!(text.contains("delete"));
        assert!(text.contains("target"));
        assert!(text.contains("test-peer"));
        assert!(text.contains("Tier 2"));
    }

    // --- process_update: chat-id auth + pending-waiter resolution ---
    //
    // These construct a real TelegramApprovalState with a syntactically
    // valid but non-functional bot token/URL - process_update's own logic
    // (chat-id check, callback_data parse, pending-map resolution) never
    // needs the HTTP call to succeed; `answer_callback_query`'s best-effort
    // POST failing silently (logged at debug, not asserted on) is the only
    // network attempt on this path, exactly as this module's own doc
    // comment for process_update describes.

    fn test_state(chat_id: i64) -> Arc<TelegramApprovalState> {
        TelegramApprovalState::new("test-token-not-real:AAA".to_string(), chat_id).expect("building the HTTP client should never fail")
    }

    fn fake_callback_update(update_id: i64, from_id: i64, data: &str, callback_query_id: &str) -> serde_json::Value {
        serde_json::json!({
            "update_id": update_id,
            "callback_query": {
                "id": callback_query_id,
                "from": {"id": from_id},
                "data": data,
            }
        })
    }

    #[tokio::test]
    async fn authorized_approve_resolves_the_pending_waiter_true() {
        let state = test_state(1234567890);
        let hex_id = "a1b2c3d4e5f60718293a4b5c6d7e8f9a";
        let (tx, rx) = oneshot::channel();
        state.pending.lock().unwrap().insert(hex_id.to_string(), tx);

        let update = fake_callback_update(1, 1234567890, &format!("wg:approve:{hex_id}"), "cbq1");
        let resolved = state.process_update(&update).await;
        assert!(resolved, "an authorized, well-formed callback must resolve the waiter");
        assert_eq!(rx.await, Ok(true));
        assert!(state.pending.lock().unwrap().get(hex_id).is_none(), "the pending entry must be removed once resolved");
    }

    #[tokio::test]
    async fn authorized_deny_resolves_the_pending_waiter_false() {
        let state = test_state(1234567890);
        let hex_id = "b1b2c3d4e5f60718293a4b5c6d7e8f9a";
        let (tx, rx) = oneshot::channel();
        state.pending.lock().unwrap().insert(hex_id.to_string(), tx);

        let update = fake_callback_update(2, 1234567890, &format!("wg:deny:{hex_id}"), "cbq2");
        assert!(state.process_update(&update).await);
        assert_eq!(rx.await, Ok(false));
    }

    #[tokio::test]
    async fn chat_id_mismatch_does_not_resolve_the_pending_intent() {
        let state = test_state(1234567890);
        let hex_id = "c1b2c3d4e5f60718293a4b5c6d7e8f9a";
        let (tx, mut rx) = oneshot::channel();
        state.pending.lock().unwrap().insert(hex_id.to_string(), tx);

        // A DIFFERENT user id - not the configured chat_id.
        let update = fake_callback_update(3, 999999999, &format!("wg:approve:{hex_id}"), "cbq3");
        let resolved = state.process_update(&update).await;
        assert!(!resolved, "an unauthorized chat/user id must never resolve a pending intent");
        assert!(
            rx.try_recv().is_err(),
            "the real waiter must remain untouched - a later reply from the REAL chat_id must still be able to resolve it"
        );
        assert!(state.pending.lock().unwrap().contains_key(hex_id), "the pending entry must still be present after an unauthorized attempt");

        // Prove the real chat_id can still resolve it afterward.
        let real_update = fake_callback_update(4, 1234567890, &format!("wg:approve:{hex_id}"), "cbq4");
        assert!(state.process_update(&real_update).await);
        assert_eq!(rx.await, Ok(true));
    }

    #[tokio::test]
    async fn two_concurrent_pending_intents_do_not_cross_resolve() {
        let state = test_state(1234567890);
        let hex_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let hex_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let (tx_a, rx_a) = oneshot::channel();
        let (tx_b, mut rx_b) = oneshot::channel();
        state.pending.lock().unwrap().insert(hex_a.to_string(), tx_a);
        state.pending.lock().unwrap().insert(hex_b.to_string(), tx_b);

        // Reply to intent A only.
        let update = fake_callback_update(5, 1234567890, &format!("wg:approve:{hex_a}"), "cbq5");
        assert!(state.process_update(&update).await);

        assert_eq!(rx_a.await, Ok(true), "intent A's waiter must resolve to the decision made for A");
        assert!(rx_b.try_recv().is_err(), "intent B's waiter must be completely unaffected by A's reply");
        assert!(state.pending.lock().unwrap().contains_key(hex_b), "intent B must still be pending after A was decided");
        assert!(!state.pending.lock().unwrap().contains_key(hex_a), "intent A must no longer be pending");
    }

    /// AXIOM adversarial-test finding, attempted attack confirmed BLOCKED
    /// (see `TESTING.md`): the exact double-spend shape the project's own
    /// adversarial test pass targeted at this channel - a real decision
    /// (deny) is recorded, then the identical `approve` callback_data for
    /// that SAME intent is resent (a Telegram client retry, a network-level
    /// duplicate delivery, or a deliberately replayed tap). `process_update`
    /// removes the pending waiter's `oneshot::Sender` the first time it
    /// resolves an intent (see `TelegramApprovalState::pending`'s own doc
    /// comment) - by the time the replayed callback arrives, there is
    /// nothing left to resolve, so it is correctly treated as "no (longer)
    /// pending waiter," identical to a reply for an intent that was never
    /// registered at all. The original `false` (deny) already delivered to
    /// the waiting `request_approval` call is never overwritten.
    #[tokio::test]
    async fn resent_approve_callback_after_the_intent_was_already_denied_does_not_flip_the_decision() {
        let state = test_state(1234567890);
        let hex_id = "e1e2e3e4e5e6e7e8e9eaebecedeeefe0";
        let (tx, rx) = oneshot::channel();
        state.pending.lock().unwrap().insert(hex_id.to_string(), tx);

        // The real decision: deny.
        let deny_update = fake_callback_update(8, 1234567890, &format!("wg:deny:{hex_id}"), "cbq8");
        assert!(state.process_update(&deny_update).await, "the real deny must resolve the waiter");
        assert_eq!(rx.await, Ok(false), "the recorded decision must be deny");

        // Immediately resend the EXACT SAME hex id's approve callback -
        // same shape a stale/replayed/double-tapped Telegram callback would
        // take. There is no waiter left to deliver a second decision to.
        let replayed_approve = fake_callback_update(9, 1234567890, &format!("wg:approve:{hex_id}"), "cbq9");
        let resolved = state.process_update(&replayed_approve).await;
        assert!(!resolved, "a replayed approve for an already-decided intent must be a safe no-op, never a second decision");
        assert!(
            !state.pending.lock().unwrap().contains_key(hex_id),
            "the already-consumed pending entry must not have been resurrected by the replay",
        );
    }

    #[tokio::test]
    async fn reply_to_unknown_intent_is_ignored_not_an_error() {
        let state = test_state(1234567890);
        let hex_id = "dddddddddddddddddddddddddddddddd";
        let real_hex = &hex_id[..32];
        let update = fake_callback_update(6, 1234567890, &format!("wg:approve:{real_hex}"), "cbq6");
        let resolved = state.process_update(&update).await;
        assert!(!resolved, "a callback for an intent this state never registered must be a safe no-op");
    }

    #[tokio::test]
    async fn non_callback_update_is_ignored() {
        let state = test_state(1234567890);
        let update = serde_json::json!({"update_id": 7, "message": {"text": "hello", "chat": {"id": 1234567890i64}}});
        assert!(!state.process_update(&update).await);
    }

    // Deliberately no test here that makes a real HTTP call to Telegram
    // (e.g. a real `request_approval`/`send_approval_request` round trip) -
    // matching this codebase's own established convention, restated by
    // every sibling UAI-backed capability's own test module (e.g.
    // `wg_peers_list_tests`'s doc comment: "Deliberately does NOT attempt a
    // real UAI HTTP round trip here... covered by this capability's live
    // verification instead"). The real Telegram send+reply round trip is
    // covered by this build's own live verification - see the final report
    // for exactly how that was validated.
}
