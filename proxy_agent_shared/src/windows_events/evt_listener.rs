// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use crate::error::Error;
use crate::logger::logger_manager;
use crate::result::Result;
use crate::windows_events::models::{EvtEvent, WindowsEvent};
use serde_json::{Map, Value};
use std::ffi::c_void;
use std::sync::{LazyLock, Mutex};
use windows_sys::Win32::Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER};
use windows_sys::Win32::System::EventLog::{
    EvtClose, EvtRender, EvtRenderEventXml, EvtSubscribe, EvtSubscribeActionDeliver,
    EvtSubscribeActionError, EvtSubscribeStartAtOldestRecord, EvtSubscribeToFutureEvents,
    EVT_HANDLE, EVT_SUBSCRIBE_NOTIFY_ACTION,
};

// ---------------------------------------------------------------------------
// Windows Event Log subscription (classic channels via the `EvtSubscribe` API).
//
// While `EtwListener` above subscribes to real-time ETW *providers*, the
// `EvtListener` type below consumes the classic Windows Event Log *channels*
// (for example `Application`, `System`, or
// `Microsoft-Windows-Sysmon/Operational`). Those channels aggregate events from
// many publishers and cannot be enabled through `EnableTraceEx2`, so they use
// the Event Log (`Evt*`) API instead. Each delivered event is rendered to XML,
// decoded into an [`WindowsEvent`], and handed to a user-supplied handler.
//
// `EvtSubscribe` delivers events asynchronously on OS thread-pool threads, so
// the `EvtListener` (which owns the callback allocation) must outlive the
// subscription: dropping it calls `EvtClose` and stops delivery. To keep a
// subscription running for the life of the process, move it into the global
// [`SUBSCRIPTIONS`] registry with [`EvtListener::keep_alive`] and tear them all
// down with [`stop`].
// ---------------------------------------------------------------------------

/// Boxed callback invoked with the decoded [`WindowsEvent`] for each delivered event.
type EventLogHandler = Box<dyn Fn(WindowsEvent) + Send + Sync + 'static>;

/// A per-source (publisher) filter: the source/provider name and the event IDs
/// to include from it. An empty `event_ids` list includes **every** event from
/// that source.
pub struct SourceFilter {
    /// Source/provider name as it appears in the event XML's `Provider @Name`
    /// (this is the "Source" column in Event Viewer), e.g. `"Application Error"`.
    pub name: String,
    /// Event IDs to include for this source; empty means all IDs.
    pub event_ids: Vec<u32>,
}

impl SourceFilter {
    /// Creates a filter for `name` limited to `event_ids` (empty = all events).
    pub fn new(name: impl Into<String>, event_ids: Vec<u32>) -> Self {
        Self {
            name: name.into(),
            event_ids,
        }
    }
}

/// A live Event Log subscription. Dropping it cancels the subscription and
/// frees the associated callback.
pub struct EvtListener {
    /// Handle returned by `EvtSubscribe`.
    subscription_handle: EVT_HANDLE,
    /// Thin pointer to the heap-allocated callback. The subscription callback
    /// dereferences this, so it must stay valid until the subscription is
    /// closed. Reclaimed in `Drop`.
    handler_ptr: *mut EventLogHandler,
}

// SAFETY: `EvtListener` owns a raw `*mut EventLogHandler` solely so `Drop` can
// reclaim the heap allocation and `EvtClose` can cancel the subscription. The
// pointed-to handler is `Fn(WindowsEvent) + Send + Sync`, and the pointer is
// never dereferenced by `EvtListener` itself (only by the OS callback, whose
// behavior is independent of which thread owns the handle). Moving the handle
// between threads is therefore sound, which lets it live in the global
// [`SUBSCRIPTIONS`] registry behind a `Mutex`.
unsafe impl Send for EvtListener {}

/// Process-wide registry that keeps `EvtListener` subscriptions alive. Because
/// `EvtSubscribe` delivers events asynchronously, a stored listener keeps
/// firing its callback until it is removed (dropped) here. Populate it with
/// [`EvtListener::keep_alive`] and drain it with [`stop`].
static SUBSCRIPTIONS: LazyLock<Mutex<Vec<EvtListener>>> = LazyLock::new(|| Mutex::new(Vec::new()));

impl EvtListener {
    /// Subscribes to an Event Log `channel`, delivering each matching event's
    /// XML to `handler`.
    ///
    /// - `channel`: channel/log name, e.g. `"Application"`, `"System"`, or
    ///   `"Microsoft-Windows-Sysmon/Operational"`.
    /// - `query`: an XPath/structured query, or `"*"` for all events in the
    ///   channel.
    /// - `include_existing`: when `true`, existing records are replayed from
    ///   the oldest record before future events; when `false`, only events
    ///   raised after subscription are delivered.
    /// - `handler`: called for every delivered event with its decoded [`WindowsEvent`].
    ///
    /// Requires permission to read the channel (the `System` channel and some
    /// others require administrator / appropriate privileges).
    pub fn subscribe_with_handler<F>(
        channel: &str,
        query: &str,
        include_existing: bool,
        handler: F,
    ) -> Result<()>
    where
        F: Fn(WindowsEvent) + Send + Sync + 'static,
    {
        let channel_wide = super::to_wide(channel);
        let query_wide = super::to_wide(query);

        // Box the callback twice: the inner box is the fat trait-object
        // pointer, the outer `into_raw` gives us a thin pointer we can pass to
        // the C callback as its context.
        let boxed: Box<EventLogHandler> = Box::new(Box::new(handler));
        let handler_ptr = Box::into_raw(boxed);

        let flags = if include_existing {
            EvtSubscribeStartAtOldestRecord
        } else {
            EvtSubscribeToFutureEvents
        };

        let subscription_handle = unsafe {
            EvtSubscribe(
                0,                            // session: local machine
                0,                            // signalevent: unused with a callback
                channel_wide.as_ptr(),        // channel path
                query_wide.as_ptr(),          // query ("*" for all events)
                0,                            // bookmark: none
                handler_ptr as *const c_void, // callback context
                Some(subscription_callback),  // delivery callback
                flags,
            )
        };

        if subscription_handle == 0 {
            let err = unsafe { GetLastError() };
            // Reclaim the callback allocation we leaked above.
            unsafe { drop(Box::from_raw(handler_ptr)) };
            return Err(Error::WindowsApi(
                format!("EvtSubscribe failed for channel '{channel}' (error {err})"),
                std::io::Error::from_raw_os_error(err as i32),
            ));
        }

        Self {
            subscription_handle,
            handler_ptr,
        }
        .keep_alive();

        logger_manager::write_info(format!("Subscribed to Event Log channel '{channel}'."));
        Ok(())
    }

    /// Convenience wrapper: subscribe to all future events in a channel.
    pub fn subscribe_channel<F>(channel: &str, handler: F) -> Result<()>
    where
        F: Fn(WindowsEvent) + Send + Sync + 'static,
    {
        Self::subscribe_with_handler(channel, "*", false, handler)
    }

    /// Convenience wrapper: subscribe to a channel filtered by a list of sources, using the default event handler.
    pub fn subscribe_by_sources(channel: &str, sources: &[SourceFilter]) -> Result<()> {
        Self::subscribe_by_sources_with_handler(channel, sources, false, |event| {
            crate::telemetry::event_logger::push_windows_event(event);
        })
    }

    /// Convenience wrapper: subscribe to a channel filtered by a list of
    /// sources, where each source carries its own list of event IDs.
    ///
    /// Semantics:
    /// - Empty `sources` slice  -> all sources (every event in the channel).
    /// - A source with empty `event_ids` -> all events from that source.
    /// - A source with event IDs -> only those IDs from that source.
    ///
    /// The sources are OR-ed together, producing a query such as:
    /// `*[System[(Provider[@Name='A'] and (EventID=1 or EventID=2)) or Provider[@Name='B']]]`.
    pub fn subscribe_by_sources_with_handler<F>(
        channel: &str,
        sources: &[SourceFilter],
        include_existing: bool,
        handler: F,
    ) -> Result<()>
    where
        F: Fn(WindowsEvent) + Send + Sync + 'static,
    {
        let query = build_source_query(sources);
        Self::subscribe_with_handler(channel, &query, include_existing, handler)
    }

    /// Moves this subscription into the process-wide [`SUBSCRIPTIONS`] registry
    /// so its callback keeps firing until [`stop`] is called (or the process
    /// exits). Without this, dropping the returned `EvtListener` immediately
    /// cancels the subscription via `EvtClose`.
    fn keep_alive(self) {
        SUBSCRIPTIONS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(self);
    }
}

/// Cancels and drops every subscription previously stored via
/// [`EvtListener::keep_alive`]. Each drop calls `EvtClose`, so no further
/// callbacks run once this returns.
pub fn stop() {
    // Take the listeners out under the lock, then drop them after releasing it
    // so each `EvtClose` (in `Drop`) runs without holding the registry mutex.
    let drained: Vec<EvtListener> = SUBSCRIPTIONS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .drain(..)
        .collect();
    let count = drained.len();
    drop(drained);
    logger_manager::write_info(format!("Stopped {count} Event Log subscription(s)."));
}

impl Drop for EvtListener {
    fn drop(&mut self) {
        unsafe {
            if self.subscription_handle != 0 {
                // `EvtClose` cancels the subscription; no further callbacks run
                // after it returns, so freeing the handler below is safe.
                EvtClose(self.subscription_handle);
                self.subscription_handle = 0;
            }
            if !self.handler_ptr.is_null() {
                drop(Box::from_raw(self.handler_ptr));
                self.handler_ptr = std::ptr::null_mut();
            }
        }
    }
}

/// Builds an XPath query from a list of source filters. Returns `"*"` (all
/// events) when `sources` is empty. Each source becomes a
/// `Provider[@Name=...]` predicate, optionally AND-ed with its event IDs, and
/// the sources are OR-ed together.
fn build_source_query(sources: &[SourceFilter]) -> String {
    if sources.is_empty() {
        return "*".to_string();
    }
    let clauses: Vec<String> = sources
        .iter()
        .map(|source| {
            let name = xpath_literal(&source.name);
            if source.event_ids.is_empty() {
                format!("Provider[@Name={name}]")
            } else {
                let ids = source
                    .event_ids
                    .iter()
                    .map(|id| format!("EventID={id}"))
                    .collect::<Vec<_>>()
                    .join(" or ");
                format!("(Provider[@Name={name}] and ({ids}))")
            }
        })
        .collect();
    format!("*[System[{}]]", clauses.join(" or "))
}

/// Produces a safe XPath 1.0 string literal for `s`, handling embedded quotes.
/// Uses `'...'`, falls back to `"..."`, and to `concat(...)` when the value
/// contains both quote characters.
pub(super) fn xpath_literal(s: &str) -> String {
    if !s.contains('\'') {
        format!("'{s}'")
    } else if !s.contains('"') {
        format!("\"{s}\"")
    } else {
        let parts: Vec<String> = s.split('\'').map(|p| format!("'{p}'")).collect();
        format!("concat({})", parts.join(", \"'\", "))
    }
}

/// C callback invoked by `wevtapi` for each delivered event or delivery error.
unsafe extern "system" fn subscription_callback(
    action: EVT_SUBSCRIBE_NOTIFY_ACTION,
    user_context: *const c_void,
    event: EVT_HANDLE,
) -> u32 {
    if user_context.is_null() {
        return 0;
    }
    let handler = &*(user_context as *const EventLogHandler);
    if action == EvtSubscribeActionDeliver {
        if let Some(xml) = render_event_xml(event) {
            match etw_event_from_event_log_xml(&xml) {
                Some(etw_event) => handler(etw_event),
                None => logger_manager::write_warn(
                    "Failed to parse Event Log XML into an WindowsEvent.".to_string(),
                ),
            }
        }
    } else if action == EvtSubscribeActionError {
        // On error, `event` carries the Win32 status of the failed delivery.
        logger_manager::write_warn(format!(
            "Event Log subscription delivery error (status {event})"
        ));
    }
    0 // ERROR_SUCCESS
}

/// Renders an event handle to its XML representation.
fn render_event_xml(event: EVT_HANDLE) -> Option<String> {
    unsafe {
        let mut buffer_used: u32 = 0;
        let mut property_count: u32 = 0;

        // First call with a zero-length buffer to learn the required size.
        let ok = EvtRender(
            0,
            event,
            EvtRenderEventXml,
            0,
            std::ptr::null_mut(),
            &mut buffer_used,
            &mut property_count,
        );
        if ok == 0 {
            let err = GetLastError();
            if err != ERROR_INSUFFICIENT_BUFFER {
                logger_manager::write_warn(format!("EvtRender size query failed (error {err})"));
                return None;
            }
        }
        if buffer_used == 0 {
            return None;
        }

        // `buffer_used` is a byte count; the payload is a UTF-16 string.
        let mut buffer = vec![0u8; buffer_used as usize];
        let ok = EvtRender(
            0,
            event,
            EvtRenderEventXml,
            buffer.len() as u32,
            buffer.as_mut_ptr() as *mut c_void,
            &mut buffer_used,
            &mut property_count,
        );
        if ok == 0 {
            let err = GetLastError();
            logger_manager::write_warn(format!("EvtRender failed (error {err})"));
            return None;
        }

        let wide =
            std::slice::from_raw_parts(buffer.as_ptr() as *const u16, buffer_used as usize / 2);
        // Trim a trailing NUL if present.
        let wide = match wide.last() {
            Some(0) => &wide[..wide.len() - 1],
            _ => wide,
        };
        Some(String::from_utf16_lossy(wide))
    }
}

/// Converts the XML rendered by `EvtRenderEventXml` into an [`WindowsEvent`], reusing
/// the Event Log XML model from [`super::models`]. Returns `None` if the
/// XML cannot be parsed. Fields that classic Event Log entries don't carry
/// (`activity_id`, `task_name`, `event_name`) are left empty/`None`.
fn etw_event_from_event_log_xml(xml: &str) -> Option<WindowsEvent> {
    let event = serde_xml_rs::from_str::<EvtEvent>(xml).ok()?;
    let system = event.system;

    let provider = system
        .provider
        .name
        .clone()
        .or_else(|| system.provider.event_source_name.clone())
        .unwrap_or_default();

    // Keywords render as a hex string such as "0x8080000000000000".
    let keyword = system
        .keywords
        .trim()
        .strip_prefix("0x")
        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
        .unwrap_or(0);

    let timestamp = match system.time_created.system_time {
        Some(ref t) if !t.is_empty() => Value::String(t.clone()),
        _ => Value::Null,
    };

    // Activity correlation ID, when the entry carries a <Correlation> element.
    let activity_id = system
        .correlation
        .as_ref()
        .and_then(|c| c.activity_id.clone())
        .unwrap_or_default();

    // Map the <Data> payload entries into named properties, preferring the
    // manifest-provided Name attribute and falling back to positional "Data{i}"
    // keys for classic (unnamed) entries.
    let mut props = Map::new();
    if let Some(items) = event.event_data.and_then(|data| data.data) {
        for (i, item) in items.into_iter().enumerate() {
            let key = match item.name {
                Some(name) if !name.is_empty() => name,
                _ => format!("Data{i}"),
            };
            props.insert(key, Value::String(item.value.unwrap_or_default()));
        }
    }

    // Modern manifest providers carry their payload in <UserData> instead of
    // <EventData>; fold the provider-defined fields into the same property map.
    if let Some(user_data) = event.user_data {
        for fields in user_data.into_values() {
            for (name, value) in fields {
                // Skip attribute noise (e.g. xmlns) captured by the generic model.
                if name.starts_with('@') {
                    continue;
                }
                props.insert(name, Value::String(value));
            }
        }
    }

    let properties = if props.is_empty() { None } else { Some(props) };

    Some(WindowsEvent {
        provider,
        event_id: system.event_id as u16,
        version: system.version,
        level: system.level,
        opcode: system.opcode,
        keyword,
        timestamp,
        process_id: system.execution.process_id,
        thread_id: system.execution.thread_id,
        activity_id,
        provider_name: system.provider.name,
        task_name: None,
        event_name: None,
        formatted_message: None, // TODO
        properties,
        user_data: None,
    })
}
