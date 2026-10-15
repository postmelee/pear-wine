/*
 * Pear native Wine bootstrap observations.
 * Copyright 2026 Pear contributors
 *
 * This Wine integration addition is free software under the GNU Lesser
 * General Public License, version 2.1 or (at your option) any later version.
 * It is provided without warranty; see Wine's COPYING.LIB for the terms.
 * This notice applies to this addition, not to a project-wide Pear license.
 */
#ifndef __WINE_PEAR_BOOTSTRAP_H
#define __WINE_PEAR_BOOTSTRAP_H

#if defined(__APPLE__) && defined(__aarch64__)
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/un.h>
#include <unistd.h>

/* The inherited pipe and nonce identify this finite diagnostic run. They
 * provide neither signing authorization nor a security boundary. */
static inline __attribute__((unused)) int pear_bootstrap_enabled(void)
{
    return getenv( "PEAR_BOOTSTRAP_FD" ) || getenv( "PEAR_BOOTSTRAP_NONCE" );
}

static inline __attribute__((unused)) long pear_bootstrap_number( const char *name, long minimum, long maximum )
{
    const char *value = getenv( name );
    char *end;
    long number;
    if (!value || !*value) _exit(125);
    for (end = (char *)value; *end; end++) if (*end < '0' || *end > '9') _exit(125);
    errno = 0;
    number = strtol( value, &end, 10 );
    if (errno || *end || number < minimum || number > maximum) _exit(125);
    return number;
}

static inline __attribute__((unused)) void pear_bootstrap_event( const char *role, const char *event, const char *details )
{
    struct proc_bsdinfo info;
    struct stat st;
    const char *nonce;
    char line[16384];
    int fd, generation, count, identity_error = 0;
    size_t length, offset = 0;
    ssize_t written;
    if (!pear_bootstrap_enabled()) return;
    nonce = getenv( "PEAR_BOOTSTRAP_NONCE" );
    if (!nonce || strlen(nonce) != 32 || strspn(nonce, "0123456789abcdef") != 32) _exit(125);
    fd = pear_bootstrap_number( "PEAR_BOOTSTRAP_FD", 3, INT_MAX );
    generation = pear_bootstrap_number( "PEAR_BOOTSTRAP_GENERATION", 0, 1 );
    if (fstat( fd, &st ) || !S_ISFIFO(st.st_mode)) _exit(125);
    memset( &info, 0, sizeof(info) );
    if (proc_pidinfo( getpid(), PROC_PIDTBSDINFO, 0, &info, sizeof(info) ) != sizeof(info))
        identity_error = errno ? errno : EIO;
    count = snprintf( line, sizeof(line),
        "{\"version\":1,\"role\":\"%s\",\"event\":\"%s\",\"nonce\":\"%s\","
        "\"pid\":%ld,\"ppid\":%ld,\"generation\":%d,\"start_sec\":%llu,\"start_usec\":%llu,"
        "\"identity_error\":%d%s}\n", role, event, nonce, (long)getpid(), (long)getppid(), generation,
        (unsigned long long)info.pbi_start_tvsec, (unsigned long long)info.pbi_start_tvusec,
        identity_error, details );
    if (count < 0 || (size_t)count >= sizeof(line)) _exit(125);
    length = count;
    while (offset < length)
    {
        written = write( fd, line + offset, length - offset );
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) _exit(125);
        offset += written;
    }
}

static inline __attribute__((unused)) void pear_bootstrap_failure( const char *role, const char *operation, int error )
{
    char detail[256];
    snprintf( detail, sizeof(detail), ",\"operation\":\"%s\",\"error\":%d", operation, error );
    pear_bootstrap_event( role, "failure", detail );
    _exit(125);
}

static inline __attribute__((unused)) void pear_bootstrap_snapshot( const char *role, const char *event )
{
    const struct mach_header *header;
    const char *prefix;
    struct stat st;
    int translated = -1, query_error = 0, prefix_error = 0;
    size_t length = sizeof(translated);
    vm_size_t kernel_page = 0;
    mach_port_t host;
    kern_return_t kernel_error;
    char detail[1024];
    if (!pear_bootstrap_enabled()) return;
    errno = 0;
    if (sysctlbyname( "sysctl.proc_translated", &translated, &length, NULL, 0 ) || length != sizeof(translated))
    {
        query_error = errno ? errno : EPROTO;
        translated = -1;
    }
    host = mach_host_self();
    kernel_error = host_page_size( host, &kernel_page );
    mach_port_deallocate( mach_task_self(), host );
    prefix = getenv( "WINEPREFIX" );
    memset( &st, 0, sizeof(st) );
    if (!prefix || prefix[0] != '/') prefix_error = EINVAL;
    else if (stat( prefix, &st )) prefix_error = errno;
    header = _dyld_get_image_header(0);
    snprintf( detail, sizeof(detail),
        ",\"cpu_type\":%d,\"translation_value\":%d,\"translation_error\":%d,"
        "\"user_page\":%ld,\"vm_page\":%lu,\"kernel_page\":%lu,\"kernel_error\":%d,"
        "\"thread_main\":%d,\"prefix_dev\":%llu,\"prefix_ino\":%llu,\"prefix_error\":%d",
        header ? header->cputype : 0, translated, query_error, sysconf(_SC_PAGESIZE),
        (unsigned long)vm_page_size, (unsigned long)kernel_page, kernel_error, pthread_main_np(),
        (unsigned long long)st.st_dev, (unsigned long long)st.st_ino, prefix_error );
    pear_bootstrap_event( role, event, detail );
}

static inline __attribute__((unused)) int pear_bootstrap_escape( char *out, size_t size, const char *input )
{
    size_t used = 0;
    const unsigned char *p = (const unsigned char *)input;
    if (!input) return 0;
    for (; *p; p++)
    {
        if (used + 7 >= size) return 0;
        if (*p == '"' || *p == '\\') { out[used++] = '\\'; out[used++] = *p; }
        else if (*p < 32) used += snprintf( out + used, size - used, "\\u%04x", *p );
        else out[used++] = *p;
    }
    out[used] = 0;
    return 1;
}

static inline __attribute__((unused)) void pear_bootstrap_images( const char *role )
{
    uint32_t i, j, count;
    char path[8192], detail[9000], uuid[33];
    if (!pear_bootstrap_enabled()) return;
    count = _dyld_image_count();
    if (count > 2048)
    {
        snprintf( detail, sizeof(detail),
                  ",\"operation\":\"image_count\",\"error\":%d,\"observed_count\":%u,\"limit\":2048",
                  EOVERFLOW, count );
        pear_bootstrap_event( role, "failure", detail );
        _exit(125);
    }
    for (i = 0; i < count; i++)
    {
        const struct mach_header_64 *header = (const void *)_dyld_get_image_header(i);
        const struct load_command *command;
        const char *end;
        uuid[0] = 0;
        if (!header || header->magic != MH_MAGIC_64 ||
            !pear_bootstrap_escape( path, sizeof(path), _dyld_get_image_name(i) ))
            pear_bootstrap_failure( role, "image_identity", EINVAL );
        command = (const void *)(header + 1);
        end = (const char *)command + header->sizeofcmds;
        for (j = 0; j < header->ncmds; j++)
        {
            if ((const char *)command + sizeof(*command) > end || command->cmdsize < sizeof(*command) ||
                (const char *)command + command->cmdsize > end)
                pear_bootstrap_failure( role, "image_commands", EINVAL );
            if (command->cmd == LC_UUID && command->cmdsize >= sizeof(struct uuid_command))
            {
                const struct uuid_command *id = (const void *)command;
                unsigned int k;
                for (k = 0; k < 16; k++) snprintf( uuid + 2 * k, 3, "%02x", id->uuid[k] );
            }
            command = (const void *)((const char *)command + command->cmdsize);
        }
        snprintf( detail, sizeof(detail), ",\"index\":%u,\"path\":\"%s\",\"cpu_type\":%d,\"uuid\":\"%s\"",
                  i, path, header->cputype, uuid );
        pear_bootstrap_event( role, "image", detail );
    }
    snprintf( detail, sizeof(detail), ",\"count\":%u", count );
    pear_bootstrap_event( role, "images_end", detail );
}

static inline __attribute__((unused)) void pear_bootstrap_memory( const void *low_mapping )
{
    const struct mach_header_64 *header = (const void *)_dyld_get_image_header(0);
    const struct load_command *command = (const void *)(header + 1);
    uint64_t guard_address = 0, guard_size = 0;
    uint32_t i;
    char detail[1024], byte;
    mach_vm_size_t copied = 0, region_size = 0;
    mach_vm_address_t address = (uintptr_t)low_mapping;
    mach_port_t object = MACH_PORT_NULL;
    vm_region_basic_info_data_64_t info = {0};
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    kern_return_t null_result, guard_result, region_result;
    if (!pear_bootstrap_enabled()) return;
    for (i = 0; i < header->ncmds; i++)
    {
        if (command->cmd == LC_SEGMENT_64)
        {
            const struct segment_command_64 *segment = (const void *)command;
            if (!strncmp( segment->segname, "__PAGEZERO", 16 ))
            { guard_address = segment->vmaddr; guard_size = segment->vmsize; }
        }
        command = (const void *)((const char *)command + command->cmdsize);
    }
    null_result = mach_vm_read_overwrite( mach_task_self(), 0, 1, (uintptr_t)&byte, &copied );
    copied = 0;
    guard_result = mach_vm_read_overwrite( mach_task_self(), 0xf000, 1, (uintptr_t)&byte, &copied );
    region_result = mach_vm_region( mach_task_self(), &address, &region_size, VM_REGION_BASIC_INFO_64,
                                   (vm_region_info_t)&info, &count, &object );
    if (object != MACH_PORT_NULL) mach_port_deallocate( mach_task_self(), object );
    snprintf( detail, sizeof(detail),
        ",\"pagezero_address\":%llu,\"pagezero_size\":%llu,\"null_read_error\":%d,"
        "\"guard_end_read_error\":%d,\"low_address\":%llu,\"region_address\":%llu,"
        "\"region_size\":%llu,\"region_protection\":%d,\"region_error\":%d",
        (unsigned long long)guard_address, (unsigned long long)guard_size, null_result, guard_result,
        (unsigned long long)(uintptr_t)low_mapping, (unsigned long long)address,
        (unsigned long long)region_size, info.protection, region_result );
    pear_bootstrap_event( "loader", "memory", detail );
}

static inline __attribute__((unused)) pid_t pear_bootstrap_peer( int socket )
{
    pid_t peer = -1;
    socklen_t size = sizeof(peer);
    long expected;
    char detail[128];
    int error;
    if (!pear_bootstrap_enabled()) return -1;
    expected = pear_bootstrap_number( "PEAR_BOOTSTRAP_SERVER_PID", 1, INT_MAX );
    error = getsockopt( socket, SOL_LOCAL, LOCAL_PEERPID, &peer, &size ) ? errno : 0;
    snprintf( detail, sizeof(detail), ",\"peer_pid\":%ld,\"peer_error\":%d", (long)peer, error );
    pear_bootstrap_event( "loader", "server_peer", detail );
    if (error || size != sizeof(peer) || peer != expected)
        pear_bootstrap_failure( "loader", "server_peer", error ? error : EPROTO );
    return peer;
}

static inline __attribute__((unused)) void pear_bootstrap_handshake( const char *role, pid_t peer, long long server_start )
{
    char detail[256];
    if (!pear_bootstrap_enabled()) return;
    snprintf( detail, sizeof(detail), ",\"peer_pid\":%ld,\"server_start\":\"%lld\"", (long)peer, server_start );
    pear_bootstrap_event( role, "server_handshake", detail );
}

static inline __attribute__((unused)) void pear_bootstrap_stop( const void *low_mapping )
{
    const char *hold;
    if (!pear_bootstrap_enabled()) return;
    pear_bootstrap_snapshot( "loader", "bootstrap_native" );
    pear_bootstrap_memory( low_mapping );
    pear_bootstrap_images( "loader" );
    if (getenv( "PEAR_STAGE3_CONTROL" ) && *getenv( "PEAR_STAGE3_CONTROL" ))
    {
        pear_bootstrap_event( "loader", "stage3_pe_continue", "" );
        return;
    }
    hold = getenv( "PEAR_BOOTSTRAP_HOLD" );
    if (hold)
    {
        if (strcmp( hold, "1" )) pear_bootstrap_failure( "loader", "hold_value", EINVAL );
        pear_bootstrap_event( "loader", "bootstrap_hold", "" );
        for (;;) pause();
    }
    pear_bootstrap_event( "loader", "bootstrap_stop", ",\"pe_entered\":false,\"foreign_mode_entered\":false" );
    _exit(0);
}
#else
#define pear_bootstrap_enabled() 0
#define pear_bootstrap_event(role,event,details) ((void)0)
#define pear_bootstrap_failure(role,operation,error) ((void)0)
#define pear_bootstrap_snapshot(role,event) ((void)0)
#define pear_bootstrap_images(role) ((void)0)
#define pear_bootstrap_peer(socket) (-1)
#define pear_bootstrap_handshake(role,peer,start) ((void)0)
#define pear_bootstrap_stop(mapping) ((void)0)
#endif
#endif
