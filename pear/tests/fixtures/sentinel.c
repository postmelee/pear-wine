/* Original Pear ordinary native sentinel. It is outside Wine's ownership set.
 * The runner closes stdin and supplies a private one-byte shutdown pipe.
 */
#include <errno.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <unistd.h>

#if !defined(__APPLE__) || !defined(__aarch64__)
#error Native ARM64 macOS is required.
#endif
extern const struct mach_header_64 _mh_execute_header;
static volatile sig_atomic_t received;
static void signal_seen(int number) { received = number; }
int main(int argc, char **argv)
{
    char *end = NULL;
    if (argc != 2) return 64;
    long control = strtol(argv[1], &end, 10);
    if (!end || *end || control < 3 || control > 1048576) return 64;
    struct sigaction action = {0};
    action.sa_handler = signal_seen;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL) ||
        sigaction(SIGHUP, &action, NULL)) return 65;
    struct proc_bsdinfo info = {0};
    int translated = -1, query_error = 0;
    size_t size = sizeof(translated);
    vm_size_t kernel_page = 0;
    mach_port_t host = mach_host_self();
    kern_return_t kernel_error = host_page_size(host, &kernel_page);
    (void)mach_port_deallocate(mach_task_self(), host);
    if (sysctlbyname("sysctl.proc_translated", &translated, &size, NULL, 0)) query_error = errno;
    else if (size != sizeof(translated)) query_error = EIO;
    if (proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &info, sizeof(info)) != sizeof(info)) return 65;
    if (printf("{\"version\":1,\"record_kind\":\"pear_sentinel_ready\",\"pid\":%d,"
               "\"ppid\":%d,\"start_sec\":%llu,\"start_usec\":%llu,\"cpu_type\":%u,"
               "\"translation_value\":%d,\"query_errno\":%d,\"user_page\":%ld,"
               "\"vm_page\":%lu,\"kernel_page\":%lu,\"kernel_error\":%d}\n",
               getpid(), getppid(), info.pbi_start_tvsec, info.pbi_start_tvusec,
               _mh_execute_header.cputype, translated, query_error, sysconf(_SC_PAGESIZE),
               (unsigned long)vm_page_size, (unsigned long)kernel_page, kernel_error) < 0 || fflush(stdout)) return 65;
    if (query_error || translated || kernel_error) return 66;
    char byte = 0;
    ssize_t count;
    do { count = read((int)control, &byte, 1); } while (count < 0 && errno == EINTR && !received);
    printf("{\"version\":1,\"record_kind\":\"pear_sentinel_done\",\"signal\":%d,\"command\":%u}\n",
           (int)received, (unsigned char)byte);
    return count == 1 && byte == 'Q' && received == 0 && fflush(stdout) == 0 ? 0 : 67;
}
