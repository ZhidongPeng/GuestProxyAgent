// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! Windows Event Log subscription built on the `EvtSubscribe` API (`wevtapi.dll`).
//!
//! Unlike [`super::etw_listener`], which subscribes to real-time ETW
//! *providers*, this reader consumes the classic Windows Event Log
//! *channels* (for example `Application`, `System`, or
//! `Microsoft-Windows-Sysmon/Operational`). Those channels aggregate events
//! from many publishers and cannot be enabled through `EnableTraceEx2`, so
//! they need the Event Log (`Evt*`) API instead.
//!
//! Each delivered event is rendered to its XML form and handed to a
//! user-supplied callback. The callback runs on an OS thread-pool thread, so
//! it must be `Send + Sync`.
//!
//! # Example
//! ```no_run
//! use proxy_agent_shared::etw::etw_subscribe::EtwSubscribe;
//!
//! // Subscribe to future events in the Application channel.
//! let _reader = EtwSubscribe::subscribe("Application", "*", false, |xml| {
//!     println!("{xml}");
//! })
//! .unwrap();
//! // Keep `_reader` alive for as long as you want to receive events.
//! ```

use crate::error::Error;
use crate::logger::logger_manager;
use crate::result::Result;
use std::ffi::c_void;
use windows_sys::Win32::Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER};
use windows_sys::Win32::System::EventLog::{
    EvtClose, EvtRender, EvtRenderEventXml, EvtSubscribe, EvtSubscribeActionDeliver,
    EvtSubscribeActionError, EvtSubscribeStartAtOldestRecord, EvtSubscribeToFutureEvents,
    EVT_HANDLE, EVT_SUBSCRIBE_NOTIFY_ACTION,
};

/// Boxed callback invoked with the rendered XML of each delivered event.
type EventHandler = Box<dyn Fn(&str) + Send + Sync + 'static>;

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
pub struct EtwSubscribe {
    /// Handle returned by `EvtSubscribe`.
    subscription: EVT_HANDLE,
    /// Thin pointer to the heap-allocated callback. The subscription callback
    /// dereferences this, so it must stay valid until the subscription is
    /// closed. Reclaimed in `Drop`.
    handler_ptr: *mut EventHandler,
}

impl EtwSubscribe {
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
    /// - `handler`: called for every delivered event with its rendered XML.
    ///
    /// Requires permission to read the channel (the `System` channel and some
    /// others require administrator / appropriate privileges).
    pub fn subscribe<F>(
        channel: &str,
        query: &str,
        include_existing: bool,
        handler: F,
    ) -> Result<Self>
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        let channel_wide = super::to_wide(channel);
        let query_wide = super::to_wide(query);

        // Box the callback twice: the inner box is the fat trait-object
        // pointer, the outer `into_raw` gives us a thin pointer we can pass to
        // the C callback as its context.
        let boxed: Box<EventHandler> = Box::new(Box::new(handler));
        let handler_ptr = Box::into_raw(boxed);

        let flags = if include_existing {
            EvtSubscribeStartAtOldestRecord
        } else {
            EvtSubscribeToFutureEvents
        };

        let subscription = unsafe {
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

        if subscription == 0 {
            let err = unsafe { GetLastError() };
            // Reclaim the callback allocation we leaked above.
            unsafe { drop(Box::from_raw(handler_ptr)) };
            return Err(Error::WindowsApi(
                format!("EvtSubscribe failed for channel '{channel}' (error {err})"),
                std::io::Error::from_raw_os_error(err as i32),
            ));
        }

        logger_manager::write_info(format!("Subscribed to Event Log channel '{channel}'."));
        Ok(Self {
            subscription,
            handler_ptr,
        })
    }

    /// Convenience wrapper: subscribe to all future events in a channel.
    pub fn subscribe_channel<F>(channel: &str, handler: F) -> Result<Self>
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        Self::subscribe(channel, "*", false, handler)
    }

    /// Convenience wrapper: subscribe to a channel limited to the given event
    /// IDs. An empty `event_ids` slice subscribes to every event in the channel.
    ///
    /// The IDs are turned into an XPath query such as
    /// `*[System[(EventID=1000 or EventID=1001)]]`. Because this is a query
    /// (not an ETW allow-list), it has no 64-ID limit and can be combined with
    /// other predicates if you build the query string yourself and call
    /// [`EtwSubscribe::subscribe`] directly.
    pub fn subscribe_by_event_ids<F>(
        channel: &str,
        event_ids: &[u32],
        include_existing: bool,
        handler: F,
    ) -> Result<Self>
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        let query = build_event_id_query(event_ids);
        Self::subscribe(channel, &query, include_existing, handler)
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
    pub fn subscribe_by_sources<F>(
        channel: &str,
        sources: &[SourceFilter],
        include_existing: bool,
        handler: F,
    ) -> Result<Self>
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        let query = build_source_query(sources);
        Self::subscribe(channel, &query, include_existing, handler)
    }
}

impl Drop for EtwSubscribe {
    fn drop(&mut self) {
        unsafe {
            if self.subscription != 0 {
                // `EvtClose` cancels the subscription; no further callbacks run
                // after it returns, so freeing the handler below is safe.
                EvtClose(self.subscription);
                self.subscription = 0;
            }
            if !self.handler_ptr.is_null() {
                drop(Box::from_raw(self.handler_ptr));
                self.handler_ptr = std::ptr::null_mut();
            }
        }
    }
}

/// Builds an XPath query selecting only the given event IDs, or `"*"` (all
/// events) when the list is empty.
fn build_event_id_query(event_ids: &[u32]) -> String {
    if event_ids.is_empty() {
        return "*".to_string();
    }
    let clause = event_ids
        .iter()
        .map(|id| format!("EventID={id}"))
        .collect::<Vec<_>>()
        .join(" or ");
    format!("*[System[({clause})]]")
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
fn xpath_literal(s: &str) -> String {
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
    let handler = &*(user_context as *const EventHandler);
    if action == EvtSubscribeActionDeliver {
        if let Some(xml) = render_event_xml(event) {
            handler(&xml);
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
