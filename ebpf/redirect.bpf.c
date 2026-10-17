// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "socket.h"

// SEC("maps")
#pragma clang section data = "maps"
struct bpf_map_def policy_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(destination_entry_t),
    .value_size = sizeof(destination_entry_t),
    .max_entries = 10};

/// Configuration map for the Guest Proxy Agent.
#pragma clang section data = "maps"
struct bpf_map_def config_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct gpa_config_entry),
    .max_entries = 1};

#pragma clang section data = "maps"
struct bpf_map_def skip_process_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(sock_addr_skip_process_entry),
    .value_size = sizeof(sock_addr_skip_process_entry),
    .max_entries = 10};

#pragma clang section data = "maps"
struct bpf_map_def audit_map = {
    .type = BPF_MAP_TYPE_LRU_HASH,             // retain the latest records automatically
    .key_size = sizeof(sock_addr_audit_key_t), // source address, port and protocol
    .value_size = sizeof(sock_addr_audit_entry_t),
    .max_entries = 1000};

/// Local map for storing local audit entries.
#pragma clang section data = "maps"
struct bpf_map_def local_map = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(uint64_t),
    .value_size = sizeof(local_audit_entry_t),
    .max_entries = 1000};

#pragma clang section data = "maps"
struct bpf_map_def alert_only_map = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .key_size = 0,
    .value_size = 0,
    .max_entries = 256 * 1024};

/*
    check the current pid in the skip_process map.
    return 1 if found, otherwise return 0.
*/
inline __attribute__((always_inline)) int
check_skip_process_map_entry(uint32_t pid)
{
    sock_addr_skip_process_entry key = {0};
    key.pid = pid;

    // Find the entry in the skip_process map.
    sock_addr_skip_process_entry *skip_entry = bpf_map_lookup_elem(&skip_process_map, &key);
    return (skip_entry != NULL) ? 1 : 0;
}

/// @brief  Check if local IP bind monitoring only is enabled in the configuration map.
/// @param  None
/// @return 1 if enabled, 0 otherwise.
inline __attribute__((always_inline)) int
local_ip_bind_monitor_only_enabled(void)
{
    uint32_t key = GPA_CONFIG_LOCAL_IP_BIND_MONITOR_ONLY;
    struct gpa_config_entry *entry = bpf_map_lookup_elem(&config_map, &key);
    return entry != NULL && entry->enabled == 1;
}

inline __attribute__((always_inline)) void
get_audit_key(const bpf_sock_addr_t *ctx, sock_addr_audit_key_t *key)
{
    key->protocol = ctx->protocol;
    key->source_port = ctx->msg_src_port;
    key->source_address_family = GPA_ADDRESS_FAMILY_IPV4;
    if (ctx->family == AF_INET6)
    {
        if (ctx->msg_src_ip6[0] == 0 &&
            ctx->msg_src_ip6[1] == 0 &&
            ctx->msg_src_ip6[2] == bpf_htonl(0x0000ffff))
        {
            key->source_ip.ipv4 = ctx->msg_src_ip6[3];
        }
        else
        {
            key->source_address_family = GPA_ADDRESS_FAMILY_IPV6;
            key->source_ip.ipv6[0] = ctx->msg_src_ip6[0];
            key->source_ip.ipv6[1] = ctx->msg_src_ip6[1];
            key->source_ip.ipv6[2] = ctx->msg_src_ip6[2];
            key->source_ip.ipv6[3] = ctx->msg_src_ip6[3];
        }
    }
    else
    {
        key->source_ip.ipv4 = ctx->msg_src_ip4;
    }
}

inline __attribute__((always_inline)) int
get_ipv4_mapped_address(const bpf_sock_addr_t *ctx, uint32_t *destination_ipv4)
{
    if (ctx->user_ip6[0] != 0 ||
        ctx->user_ip6[1] != 0 ||
        ctx->user_ip6[2] != bpf_htonl(0x0000ffff))
    {
        return 0;
    }

    *destination_ipv4 = ctx->user_ip6[3];
    return 1;
}

inline __attribute__((always_inline)) void
trace_audit_tuple(const bpf_sock_addr_t *ctx, const sock_addr_audit_key_t *key,
                  uint64_t cookie, uint32_t stage)
{
    bpf_printk("Audit stage=%u cookie=%llu protocol=%u.", stage, cookie, key->protocol);
    bpf_printk("Audit source cookie=%llu family=%u port=%u.",
               cookie, key->source_address_family, bpf_ntohs((uint16_t)key->source_port));
    bpf_printk("Audit source cookie=%llu ip0=%x ip1=%x.",
               cookie, bpf_ntohl(key->source_ip.ipv6[0]), bpf_ntohl(key->source_ip.ipv6[1]));
    bpf_printk("Audit source cookie=%llu ip2=%x ip3=%x.",
               cookie, bpf_ntohl(key->source_ip.ipv6[2]), bpf_ntohl(key->source_ip.ipv6[3]));
    uint32_t destination_ipv4 = ctx->user_ip4;
    if (ctx->family == AF_INET6 && !get_ipv4_mapped_address(ctx, &destination_ipv4))
    {
        bpf_printk("Audit destination cookie=%llu is native IPv6.", cookie);
        return;
    }
    bpf_printk("Audit destination cookie=%llu ip=%x port=%u.",
               cookie, bpf_ntohl(destination_ipv4), bpf_ntohs((uint16_t)ctx->user_port));
}

inline __attribute__((always_inline)) int
audit_matches_authorization(bpf_sock_addr_t *ctx, const local_audit_entry_t *entry, uint64_t cookie)
{
    uint32_t destination_ipv4 = ctx->user_ip4;
    if (ctx->family == AF_INET6 && !get_ipv4_mapped_address(ctx, &destination_ipv4))
    {
        bpf_printk("Deferred audit cookie=%llu: native IPv6 destination.", cookie);
        return 0;
    }
    if (ctx->protocol != entry->protocol ||
        destination_ipv4 != entry->redirect_ipv4 || ctx->user_port != entry->redirect_port)
    {
        bpf_printk("Deferred audit cookie=%llu: protocol or redirected destination mismatch.", cookie);
        bpf_printk("Expected redirect cookie=%llu ip=%x port=%u.",
                   cookie, bpf_ntohl(entry->redirect_ipv4), bpf_ntohs((uint16_t)entry->redirect_port));
        return 0;
    }

    // These IDs come from WFP metadata, not the worker task.
    uint32_t process_id = (uint32_t)(bpf_get_current_pid_tgid() >> 32);
    uint32_t logon_id = (uint32_t)bpf_get_current_logon_id(ctx);
    if (process_id != entry->audit.process_id || logon_id != entry->audit.logon_id)
    {
        bpf_printk("Unmatched authorization cookie=%llu pid=%u expected=%u.",
                   cookie, process_id, entry->audit.process_id);
        bpf_printk("Unmatched authorization cookie=%llu logon=%u expected=%u.",
                   cookie, logon_id, entry->audit.logon_id);
        return 0;
    }
    return 1;
}

/*
    Capture audit context and stage it by socket cookie before redirecting.
    return 0 to continue redirecting, otherwise
    return 1 if pid found in the skip_process_map.
*/
inline __attribute__((always_inline)) int
update_audit_map_entry(bpf_sock_addr_t *ctx, uint32_t destination_ipv4, uint32_t address_family,
                       int alert_only, const destination_entry_t *policy)
{
    uint64_t pid_tip = bpf_get_current_pid_tgid();
    uint32_t pid = (uint32_t)(pid_tip >> 32);

    if (check_skip_process_map_entry(pid) == 1)
    {
        return 1;
    }

    sock_addr_audit_entry_t entry = {0};
    entry.process_id = pid;
    entry.logon_id = (uint32_t)bpf_get_current_logon_id(ctx);
    if (entry.logon_id == 0)
    {
        bpf_printk("Failed to get logon id.");
    }
    int32_t is_admin = bpf_is_current_admin(ctx);
    if (is_admin < 0)
    {
        bpf_printk("Failed to get admin status %d.", is_admin);
        entry.is_root = 0;
    }
    else
    {
        entry.is_root = (is_admin > 0) ? 1 : 0;
    }
    entry.destination_ipv4 = destination_ipv4;
    entry.destination_port = ctx->user_port;
    entry.address_family = address_family;
    if (alert_only)
    {
        // if alert_only, emit an alert-only event to the ring buffer.
        struct gpa_alert_only_event event = {0};
        event.kernel_timestamp_ns = bpf_ktime_get_ns();
        event.local_ip_address[0] = ctx->msg_src_ip4;
        event.audit = entry;
        uint64_t ret = bpf_ringbuf_output(&alert_only_map, &event, sizeof(event), 0);
        if (ret != 0)
        {
            bpf_printk("Failed to emit alert-only event with results: %u.", ret);
        }
        return 0;
    }

    uint64_t cookie = bpf_get_socket_cookie(ctx);
    if (cookie == 0)
    {
        bpf_printk("Cannot stage audit: redirect socket cookie is zero.");
        // Missing socket cookie; using audit redirect context.
        //  Keep the socket-bound path available even when authorization publishes a map entry.
        int32_t result = bpf_sock_addr_set_redirect_context(ctx, &entry, sizeof(entry));
        if (result != 0)
        {
            bpf_printk("Failed to add audit redirect context: %d.", result);
        }

        return 0;
    }

    local_audit_entry_t local_entry = {0};
    local_entry.audit = entry;
    local_entry.protocol = ctx->protocol;
    local_entry.redirect_ipv4 = policy->destination_ip.ipv4;
    local_entry.redirect_port = policy->destination_port;
    sock_addr_audit_key_t key = {0};
    get_audit_key(ctx, &key);
    trace_audit_tuple(ctx, &key, cookie, 0);
    int64_t ret = bpf_map_update_elem(&local_map, &cookie, &local_entry, BPF_NOEXIST);
    if (ret != 0)
    {
        bpf_printk("Failed to stage audit cookie=%llu result=%lld.", cookie, ret);
    }
    else
    {
        bpf_printk("Staged audit cookie=%llu pid=%u logon=%u.", cookie, pid, entry.logon_id);
    }

    return 0;
}

inline __attribute__((always_inline)) int
publish_audit_entry(bpf_sock_addr_t *ctx)
{
    uint64_t cookie = bpf_get_socket_cookie(ctx);
    bpf_printk("Audit authorization cookie=%llu.", cookie);
    if (cookie == 0)
    {
        bpf_printk("Cannot publish audit: authorization socket cookie is zero.");
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }

    local_audit_entry_t *stored = bpf_map_lookup_elem(&local_map, &cookie);
    if (stored == NULL)
    {
        bpf_printk("No staged audit cookie=%llu.", cookie);
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }
    local_audit_entry_t local_entry = *stored;
    sock_addr_audit_key_t key = {0};
    get_audit_key(ctx, &key);
    trace_audit_tuple(ctx, &key, cookie, 1);

    if (key.source_port == 0 ||
        (key.source_ip.ipv6[0] == 0 && key.source_ip.ipv6[1] == 0 &&
         key.source_ip.ipv6[2] == 0 && key.source_ip.ipv6[3] == 0))
    {
        bpf_printk("Deferred audit cookie=%llu: source address or port is unresolved.", cookie);
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }

    if (!audit_matches_authorization(ctx, &local_entry, cookie))
    {
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }

    // An earlier authorization callback may describe the original destination.
    // Only the matching redirected callback can claim the pending identity.
    stored = bpf_map_lookup_and_delete_elem(&local_map, &cookie);
    if (stored == NULL)
    {
        bpf_printk("Audit cookie=%llu was already consumed.", cookie);
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }
    local_entry = *stored;
    if (!audit_matches_authorization(ctx, &local_entry, cookie))
    {
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }

    int64_t ret = bpf_map_update_elem(&audit_map, &key, &local_entry.audit, BPF_NOEXIST);
    if (ret != 0)
    {
        bpf_printk("Failed to publish audit cookie=%llu result=%lld.", cookie, ret);
    }
    else
    {
        bpf_printk("Published audit cookie=%llu protocol=%u port=%u.",
                   cookie, key.protocol, bpf_ntohs((uint16_t)key.source_port));
    }
    return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
}

inline __attribute__((always_inline)) int
authorize_v4(bpf_sock_addr_t *ctx)
{
    destination_entry_t entry = {0};
    entry.destination_ip.ipv4 = ctx->user_ip4;
    entry.destination_port = ctx->user_port;
    entry.protocol = ctx->protocol;

    // Find the entry in the policy map.
    destination_entry_t *policy = bpf_map_lookup_elem(&policy_map, &entry);
    if (policy != NULL)
    {
        bpf_printk("Found v4 proxy entry value: %u, %u", policy->destination_ip.ipv4, policy->destination_port);

        uint32_t source_ip = ctx->msg_src_ip4;
        int bind_to_local_ip = source_ip != 0 && (source_ip & 0xff) != 0x7f; // check if the source ip is set and not loopback
        if (bind_to_local_ip)
        {
            // emit an alert-only event for binding to the local IP.
            if (update_audit_map_entry(ctx, ctx->user_ip4, GPA_ADDRESS_FAMILY_IPV4, 1, policy) == 1)
            {
                bpf_printk("Found skip process entry, skip the redirection.");
                return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
            }

            // if config set to alert only, skip the redirection.
            if (local_ip_bind_monitor_only_enabled())
            {
                bpf_printk("Source address is explicitly bound, alert without redirecting.");
                return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
            }
        }

        // update to the audit map before changing the destination ip and port.
        if (update_audit_map_entry(ctx, ctx->user_ip4, GPA_ADDRESS_FAMILY_IPV4, 0, policy) == 1)
        {
            bpf_printk("Found skip process entry, skip the redirection.");
            return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
        }

        bpf_printk("redirecting to destination loopback ip.");
        ctx->user_ip4 = policy->destination_ip.ipv4;
        ctx->user_port = policy->destination_port;
    }

    return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
}

// SEC("cgroup/connect4")
#pragma clang section text = "cgroup/connect4"
int authorize_connect4(bpf_sock_addr_t *ctx)
{
    return authorize_v4(ctx);
}

// SEC("cgroup/connect6")
#pragma clang section text = "cgroup/connect6"
int authorize_connect6(bpf_sock_addr_t *ctx)
{
    // Check if the destination address is an IPv4-mapped IPv6 address.
    // While the current eBPF_for_Windows detects the IPv4-mapped address,
    // explicitly classify/convert dual-stack IPv4-mapped connections as IPv4.
    // refer to https://github.com/microsoft/ebpf-for-windows/issues/5536
    // We keep this logic here to support dual-stack IPv4-mapped connections in connect6,
    // just in case windows eBPF may change the behavior to align with Linux eBPF.
    uint32_t destination_ipv4;
    if (get_ipv4_mapped_address(ctx, &destination_ipv4) == 0)
    {
        // Native IPv6 destinations are not redirected by the IPv4 policy map.
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }

    destination_entry_t entry = {0};
    entry.destination_ip.ipv4 = destination_ipv4;
    entry.destination_port = ctx->user_port;
    entry.protocol = ctx->protocol;

    destination_entry_t *policy = bpf_map_lookup_elem(&policy_map, &entry);
    if (policy != NULL)
    {
        // TODO: handle bind to Local IPv6 address before redirecting.

        bpf_printk("Found IPv4-mapped proxy entry.");
        if (update_audit_map_entry(ctx, destination_ipv4, GPA_ADDRESS_FAMILY_IPV6, 0, policy) == 1)
        {
            bpf_printk("Found skip process entry, skip the redirection.");
            return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
        }

        ctx->user_ip6[0] = 0;
        ctx->user_ip6[1] = 0;
        ctx->user_ip6[2] = bpf_htonl(0x0000ffff);
        ctx->user_ip6[3] = policy->destination_ip.ipv4;
        ctx->user_port = policy->destination_port;
    }

    return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
}

#pragma clang section text = "cgroup/connect_authorization4"
int audit_authorization4(bpf_sock_addr_t *ctx)
{
    bpf_printk("Entered audit_authorization4.");
    return publish_audit_entry(ctx);
}

#pragma clang section text = "cgroup/connect_authorization6"
int audit_authorization6(bpf_sock_addr_t *ctx)
{
    bpf_printk("Entered audit_authorization6.");
    return publish_audit_entry(ctx);
}
