/*
 * Pear finite native Wine process observations.
 * Copyright 2026 Pear contributors
 *
 * This Wine integration addition is free software under the GNU Lesser
 * General Public License, version 2.1 or (at your option) any later version.
 * It is provided without warranty; see Wine's COPYING.LIB for the terms.
 */
#ifndef __WINE_PEAR_STAGE3_H
#define __WINE_PEAR_STAGE3_H
#include "wine/pear_bootstrap.h"
#if defined(__APPLE__) && defined(__aarch64__)
#include <poll.h>
#include <sys/time.h>
#include <sys/wait.h>

/* These hooks constrain only the explicitly selected, instrumented suite.
 * They do not implement a product supervisor or silently replace wineboot. */
static inline __attribute__((unused)) int pear_stage3_enabled(void)
{
    const char *value = getenv( "PEAR_STAGE3_CONTROL" );
    return value && *value;
}

static inline __attribute__((unused)) void pear_stage3_register( const char *kind )
{
    const char *endpoint = getenv( "PEAR_STAGE3_CONTROL" ), *registered, *nonce;
    struct sockaddr_un address;
    struct proc_bsdinfo info;
    struct timeval timeout = {30, 0};
    struct iovec iov;
    struct msghdr message;
    struct cmsghdr *control;
    char buffer[CMSG_SPACE(sizeof(int))], hello[2048], pid_text[32], fd_text[32], reply;
    int socket_fd, event_fd = -1, length, translated = -1, query_error = 0;
    size_t query_size = sizeof(translated);
    vm_size_t kernel_page = 0;
    mach_port_t host;
    kern_return_t kernel_error;
    if (!pear_stage3_enabled()) return;
    snprintf( pid_text, sizeof(pid_text), "%ld", (long)getpid() );
    registered = getenv( "PEAR_STAGE3_REGISTERED_PID" );
    if (registered && !strcmp( registered, pid_text ))
    {
        struct stat retained;
        int fd = pear_bootstrap_number( "PEAR_BOOTSTRAP_FD", 3, INT_MAX );
        if (fstat( fd, &retained ) || !S_ISFIFO(retained.st_mode) ||
            fcntl( fd, F_GETFD ) & FD_CLOEXEC) _exit(125);
        return;
    }
    nonce = getenv( "PEAR_BOOTSTRAP_NONCE" );
    if (!nonce || strlen(nonce) != 32 || strspn(nonce, "0123456789abcdef") != 32 ||
        endpoint[0] != '/' || strlen(endpoint) >= sizeof(address.sun_path)) _exit(125);
    if (getenv( "PEAR_BOOTSTRAP_FD" ))
        close( pear_bootstrap_number( "PEAR_BOOTSTRAP_FD", 3, INT_MAX ) );
    memset( &info, 0, sizeof(info) );
    if (proc_pidinfo( getpid(), PROC_PIDTBSDINFO, 0, &info, sizeof(info)) != sizeof(info)) _exit(125);
    if (sysctlbyname( "sysctl.proc_translated", &translated, &query_size, NULL, 0 ) ||
        query_size != sizeof(translated)) query_error = errno ? errno : EPROTO;
    host = mach_host_self();
    kernel_error = host_page_size( host, &kernel_page );
    mach_port_deallocate( mach_task_self(), host );
    length = snprintf( hello, sizeof(hello),
        "{\"version\":1,\"kind\":\"%s\",\"nonce\":\"%s\",\"pid\":%ld,\"ppid\":%ld,"
        "\"start_sec\":%llu,\"start_usec\":%llu,\"pgid\":%ld,\"cpu_type\":%d,"
        "\"translation_value\":%d,\"translation_error\":%d,\"user_page\":%ld,"
        "\"vm_page\":%lu,\"kernel_page\":%lu,\"kernel_error\":%d}\n",
        kind, nonce, (long)getpid(), (long)getppid(),
        (unsigned long long)info.pbi_start_tvsec, (unsigned long long)info.pbi_start_tvusec,
        (long)getpgrp(), _dyld_get_image_header(0)->cputype, translated, query_error,
        sysconf(_SC_PAGESIZE), (unsigned long)vm_page_size, (unsigned long)kernel_page, kernel_error );
    if (length <= 0 || (size_t)length >= sizeof(hello)) _exit(125);
    socket_fd = socket( AF_UNIX, SOCK_STREAM, 0 );
    if (socket_fd == -1) _exit(125);
    memset( &address, 0, sizeof(address) );
    address.sun_family = AF_UNIX;
    address.sun_len = sizeof(address);
    strcpy( address.sun_path, endpoint );
    if (setsockopt( socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout) ) ||
        setsockopt( socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout) ) ||
        connect( socket_fd, (const struct sockaddr *)&address, sizeof(address) ) ||
        write( socket_fd, hello, length ) != length) _exit(125);
    memset( &message, 0, sizeof(message) );
    memset( buffer, 0, sizeof(buffer) );
    iov.iov_base = &reply;
    iov.iov_len = 1;
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = buffer;
    message.msg_controllen = sizeof(buffer);
    if (recvmsg( socket_fd, &message, 0 ) != 1 || reply != 'G' ||
        message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) _exit(125);
    control = CMSG_FIRSTHDR( &message );
    if (!control || control->cmsg_level != SOL_SOCKET || control->cmsg_type != SCM_RIGHTS ||
        control->cmsg_len != CMSG_LEN(sizeof(int)) || CMSG_NXTHDR(&message, control)) _exit(125);
    memcpy( &event_fd, CMSG_DATA(control), sizeof(event_fd) );
    if (event_fd < 3 || fcntl( event_fd, F_SETFD, 0 )) _exit(125);
    close( socket_fd );
    snprintf( fd_text, sizeof(fd_text), "%d", event_fd );
    if (setenv( "PEAR_BOOTSTRAP_FD", fd_text, 1 ) ||
        setenv( "PEAR_STAGE3_REGISTERED_PID", pid_text, 1 )) _exit(125);
    if (!strcmp( kind, "fork" ))
    {
        pear_bootstrap_snapshot( "loader", "stage3_fork" );
        pear_bootstrap_images( "loader" );
    }
}

/* Parent remains alive until the registered child is acknowledged. This also
 * keeps the short-lived intermediate process attributable during double-fork.
 * No child executes PE or performs another fork before that acknowledgement. */
static inline __attribute__((unused)) pid_t pear_stage3_fork(void)
{
    int ready[2];
    pid_t pid;
    char acknowledgement;
    struct pollfd poll_fd;
    if (!pear_stage3_enabled()) return fork();
    if (pipe( ready )) return -1;
    pid = fork();
    if (!pid)
    {
        close( ready[0] );
        if (setenv( "PEAR_BOOTSTRAP_GENERATION", "0", 1 )) _exit(125);
        pear_stage3_register( "fork" );
        if (write( ready[1], "R", 1 ) != 1) _exit(125);
        close( ready[1] );
        return 0;
    }
    close( ready[1] );
    if (pid > 0)
    {
        poll_fd.fd = ready[0];
        poll_fd.events = POLLIN;
        poll_fd.revents = 0;
        if (poll( &poll_fd, 1, 35000 ) <= 0 || read( ready[0], &acknowledgement, 1 ) != 1 ||
            acknowledgement != 'R') _exit(125);
    }
    close( ready[0] );
    return pid;
}

static inline __attribute__((unused)) pid_t pear_stage3_setsid(void)
{
    /* Keep descendants inside the unreaped root's reserved process group.
     * Console/stdio behavior is otherwise unchanged; ordinary runs use setsid. */
    return pear_stage3_enabled() ? getpgrp() : setsid();
}
#else
#define pear_stage3_enabled() 0
#define pear_stage3_register(kind) ((void)0)
#define pear_stage3_fork() fork()
#define pear_stage3_setsid() setsid()
#endif
#endif
