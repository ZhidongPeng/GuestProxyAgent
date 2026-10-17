// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"
#include "bpf_endian.h"
#undef memcpy
#undef memset
#undef memcmp
#include <assert.h>
#include <stdio.h>
#include <string.h>

void *test_lookup(void *map, const void *key);
void *test_take(void *map, const void *key);
int64_t test_update(void *map, const void *key, const void *value, uint64_t flags);
int test_context(bpf_sock_addr_t *ctx, void *data, uint32_t size);
uint64_t test_cookie(void *ctx);
uint64_t test_pid(void);
uint64_t test_logon(void *ctx);
int test_alert(void *map, void *data, uint64_t size, uint64_t flags);

#undef bpf_map_lookup_elem
#undef bpf_map_lookup_and_delete_elem
#undef bpf_map_update_elem
#undef bpf_sock_addr_set_redirect_context
#undef bpf_get_socket_cookie
#undef bpf_get_current_pid_tgid
#undef bpf_get_current_logon_id
#undef bpf_is_current_admin
#undef bpf_ktime_get_ns
#undef bpf_ringbuf_output
#undef bpf_printk
#define bpf_map_lookup_elem test_lookup
#define bpf_map_lookup_and_delete_elem test_take
#define bpf_map_update_elem test_update
#define bpf_sock_addr_set_redirect_context test_context
#define bpf_get_socket_cookie test_cookie
#define bpf_get_current_pid_tgid test_pid
#define bpf_get_current_logon_id test_logon
#define bpf_is_current_admin(ctx) 1
#define bpf_ktime_get_ns() 1
#define bpf_ringbuf_output test_alert
#define bpf_printk(...) ((void)0)

#include "..\redirect.bpf.c"

#pragma clang section text = ""
#pragma clang section data = ""
#pragma clang section bss = ""
#pragma clang section rodata = ""

static sock_addr_audit_entry_t context;
static local_audit_entry_t staged;
static sock_addr_audit_entry_t published;
static sock_addr_audit_key_t published_key;
static uint64_t current_cookie;
static uint64_t staged_cookie;
static uint32_t current_pid;
static uint32_t current_logon;
static int context_calls;
static int stage_calls;
static int staged_present;
static int take_calls;
static int publication_calls;
static int published_present;
static int fail_stage;
static int fail_publication;
static int skip_process;
static int alerts;
static int in_authorization;

void *test_lookup(void *map, const void *key)
{
    if (map == &local_map)
        return staged_present && *(const uint64_t *)key == staged_cookie ? &staged : NULL;
    assert(map == &skip_process_map);
    return skip_process ? &skip_process : NULL;
}

void *test_take(void *map, const void *key)
{
    assert(map == &local_map);
    take_calls++;
    if (test_lookup(map, key) == NULL)
        return NULL;
    staged_present = 0;
    return &staged;
}

int64_t test_update(void *map, const void *key, const void *value, uint64_t flags)
{
    assert(flags == BPF_NOEXIST);
    if (map == &audit_map)
    {
        publication_calls++;
        if (fail_publication)
            return -12;
        published = *(const sock_addr_audit_entry_t *)value;
        published_key = *(const sock_addr_audit_key_t *)key;
        published_present = 1;
        return 0;
    }
    assert(map == &local_map && *(const uint64_t *)key == current_cookie);
    stage_calls++;
    if (fail_stage)
        return -12;
    staged_cookie = *(const uint64_t *)key;
    staged = *(const local_audit_entry_t *)value;
    staged_present = 1;
    return 0;
}

int test_context(bpf_sock_addr_t *ctx, void *data, uint32_t size)
{
    assert(ctx != NULL && size == sizeof(context));
    assert(stage_calls == 0 && !in_authorization);
    context_calls++;
    memcpy(&context, data, size);
    return 0;
}

uint64_t test_cookie(void *ctx)
{
    assert(ctx != NULL);
    return current_cookie;
}

uint64_t test_pid(void)
{
    return (uint64_t)current_pid << 32;
}

uint64_t test_logon(void *ctx)
{
    assert(ctx != NULL);
    return current_logon;
}

int test_alert(void *map, void *data, uint64_t size, uint64_t flags)
{
    assert(map == &alert_only_map && data != NULL);
    assert(size == sizeof(struct gpa_alert_only_event) && flags == 0);
    alerts++;
    return 0;
}

static void reset(void)
{
    memset(&context, 0, sizeof(context));
    current_cookie = 0x100000001ULL;
    current_pid = 123;
    current_logon = 456;
    context_calls = stage_calls = staged_present = publication_calls = take_calls = 0;
    published_present = skip_process = alerts = in_authorization = 0;
    fail_stage = fail_publication = 0;
}

static void set_destination(bpf_sock_addr_t *ctx, uint32_t ip, uint16_t port)
{
    ctx->user_port = bpf_htons(port);
    if (ctx->family == AF_INET6)
    {
        memset(ctx->user_ip6, 0, sizeof(ctx->user_ip6));
        ctx->user_ip6[2] = bpf_htonl(0x0000ffff);
        ctx->user_ip6[3] = bpf_htonl(ip);
    }
    else
        ctx->user_ip4 = bpf_htonl(ip);
}

static void stage_connection(bpf_sock_addr_t *ctx, uint32_t family)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->family = family;
    ctx->protocol = IPPROTO_TCP;
    set_destination(ctx, 0xa83f8110, 80);
    destination_entry_t policy = {
        .destination_ip.ipv4 = bpf_htonl(0x7f000001),
        .destination_port = bpf_htons(3080),
        .protocol = IPPROTO_TCP,
    };
    uint32_t address_family = family == AF_INET ? GPA_ADDRESS_FAMILY_IPV4 : GPA_ADDRESS_FAMILY_IPV6;
    assert(update_audit_map_entry(ctx, bpf_htonl(0xa83f8110), address_family, 0, &policy) == 0);
    set_destination(ctx, 0x7f000001, 3080);
    ctx->msg_src_port = bpf_htons(49363);
    if (family == AF_INET6)
    {
        ctx->msg_src_ip6[2] = bpf_htonl(0x0000ffff);
        ctx->msg_src_ip6[3] = bpf_htonl(0x7f000001);
    }
    else
        ctx->msg_src_ip4 = bpf_htonl(0x7f000001);
    in_authorization = 1;
}

static void expect_deferred(bpf_sock_addr_t *ctx)
{
    assert(publish_audit_entry(ctx) == BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT);
    assert(staged_present && take_calls == 0 && publication_calls == 0 && context_calls == 0);
}

static void expect_published(bpf_sock_addr_t *ctx)
{
    assert(publish_audit_entry(ctx) == BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT);
    assert(!staged_present && take_calls == 1 && publication_calls == 1 && published_present);
    assert(context_calls == 0);
    assert(published.process_id == 123 && published.logon_id == 456 && published.is_root == 1);
    assert(published.destination_ipv4 == bpf_htonl(0xa83f8110));
    assert(published.destination_port == bpf_htons(80));
    assert(published_key.protocol == IPPROTO_TCP);
    assert(published_key.source_address_family == GPA_ADDRESS_FAMILY_IPV4);
    assert(published_key.source_port == bpf_htons(49363));
    assert(published_key.source_ip.ipv4 == bpf_htonl(0x7f000001));
    assert(published_key.source_ip.ipv6[1] == 0);
    assert(published_key.source_ip.ipv6[2] == 0);
    assert(published_key.source_ip.ipv6[3] == 0);
    assert(publish_audit_entry(ctx) == BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT);
    assert(take_calls == 1 && publication_calls == 1);
}

static void test_primary(uint32_t family)
{
    reset();
    bpf_sock_addr_t ctx;
    stage_connection(&ctx, family);
    expect_published(&ctx);

    reset();
    stage_connection(&ctx, family);
    // WFP may authorize the original destination before the redirected tuple.
    set_destination(&ctx, 0xa83f8110, 80);
    expect_deferred(&ctx);
    set_destination(&ctx, 0x7f000001, 3080);
    expect_published(&ctx);

    reset();
    stage_connection(&ctx, family);
    ctx.msg_src_port = 0;
    expect_deferred(&ctx);
    ctx.msg_src_port = bpf_htons(49363);
    expect_published(&ctx);

    reset();
    stage_connection(&ctx, family);
    uint32_t source[4];
    memcpy(source, ctx.msg_src_ip6, sizeof(source));
    memset(ctx.msg_src_ip6, 0, sizeof(ctx.msg_src_ip6));
    expect_deferred(&ctx);
    memcpy(ctx.msg_src_ip6, source, sizeof(source));
    expect_published(&ctx);

    reset();
    stage_connection(&ctx, family);
    current_pid++;
    expect_deferred(&ctx);
    current_pid--;
    current_logon++;
    expect_deferred(&ctx);
    current_logon--;
    ctx.protocol = IPPROTO_UDP;
    expect_deferred(&ctx);
    ctx.protocol = IPPROTO_TCP;
    ctx.user_port = bpf_htons(3081);
    expect_deferred(&ctx);
    ctx.user_port = bpf_htons(3080);
    expect_published(&ctx);

    reset();
    stage_connection(&ctx, family);
    current_cookie++;
    expect_deferred(&ctx);
    current_cookie--;
    expect_published(&ctx);

    reset();
    stage_connection(&ctx, family);
    fail_publication = 1;
    assert(publish_audit_entry(&ctx) == BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT);
    assert(!staged_present && !published_present && publication_calls == 1 && context_calls == 0);
}

int main(void)
{
    for (int ipv6 = 0; ipv6 < 2; ipv6++)
    {
        uint32_t family = ipv6 ? AF_INET6 : AF_INET;
        test_primary(family);
    }
    reset();
    bpf_sock_addr_t mapped;
    stage_connection(&mapped, AF_INET6);
    mapped.user_ip6[0] = bpf_htonl(0x20010db8);
    expect_deferred(&mapped);
    mapped.family = AF_INET;
    set_destination(&mapped, 0x7f000001, 3080);
    memset(mapped.msg_src_ip6, 0, sizeof(mapped.msg_src_ip6));
    mapped.msg_src_ip4 = bpf_htonl(0x7f000001);
    expect_published(&mapped);
    assert(published.address_family == GPA_ADDRESS_FAMILY_IPV6);

    reset();
    current_cookie = 0;
    bpf_sock_addr_t zero_cookie;
    stage_connection(&zero_cookie, AF_INET);
    assert(context_calls == 1 && stage_calls == 0);

    reset();
    fail_stage = 1;
    stage_connection(&zero_cookie, AF_INET);
    assert(stage_calls == 1 && !staged_present && context_calls == 0);
    assert(publish_audit_entry(&zero_cookie) == BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT);
    assert(!published_present && publication_calls == 0);

    reset();
    bpf_sock_addr_t ctx = {0};
    destination_entry_t policy = {0};
    context_calls = stage_calls = 0;
    skip_process = 1;
    assert(update_audit_map_entry(&ctx, 0, GPA_ADDRESS_FAMILY_IPV4, 0, &policy) == 1);
    assert(context_calls == 0 && stage_calls == 0);
    skip_process = 0;
    assert(update_audit_map_entry(&ctx, 0, GPA_ADDRESS_FAMILY_IPV4, 1, &policy) == 0);
    assert(alerts == 1 && context_calls == 0 && stage_calls == 0);
    puts("Windows primary cookie-path regression tests passed without socket context.");
    return 0;
}
