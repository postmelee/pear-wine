/* Original Pear Stage 3 ownership helper. It executes the real Wine loader;
 * its observations do not qualify Wine, PE execution, x18 or game support.
 * The 4 KiB spawn-attribute pattern is reused from host/probe/child_runner.c.
 */
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <unistd.h>

#if !defined(__APPLE__) || !defined(__aarch64__)
#error Native ARM64 macOS is required.
#endif
extern char **environ;
extern const struct mach_header_64 _mh_execute_header;

static int observe(void)
{
    struct proc_bsdinfo info = {0};
    int translated = -1, query_error = 0;
    size_t size = sizeof(translated);
    vm_size_t kernel_page = 0;
    mach_port_t host = mach_host_self();
    kern_return_t kernel_error = host_page_size(host, &kernel_page);
    (void)mach_port_deallocate(mach_task_self(), host);
    if (sysctlbyname("sysctl.proc_translated", &translated, &size, NULL, 0) != 0)
        query_error = errno;
    else if (size != sizeof(translated)) query_error = EIO;
    if (proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &info, sizeof(info)) != sizeof(info)) return 1;
    if (printf("{\"version\":1,\"record_kind\":\"pear_bootstrap_helper\",\"pid\":%d,"
               "\"ppid\":%d,\"start_sec\":%llu,\"start_usec\":%llu,\"cpu_type\":%u,"
               "\"translation_value\":%d,\"query_errno\":%d,\"user_page\":%ld,"
               "\"vm_page\":%lu,\"kernel_page\":%lu,\"kernel_error\":%d}\n",
               getpid(), getppid(), info.pbi_start_tvsec, info.pbi_start_tvusec,
               _mh_execute_header.cputype, translated, query_error, sysconf(_SC_PAGESIZE),
               (unsigned long)vm_page_size, (unsigned long)kernel_page, kernel_error) < 0 || fflush(stdout)) return 1;
    return query_error || translated != 0 || kernel_error ? 1 : 0;
}

int main(int argc, char **argv)
{
    typedef int (*set_page_mode_fn)(const posix_spawnattr_t *);
    if (argc == 2 && !strcmp(argv[1], "--observe")) return observe();
    if (argc < 4 || strcmp(argv[1], "--exec-4k") || argv[2][0] != '/') return 64;
    struct stat target;
    if (lstat(argv[2], &target) || !S_ISREG(target.st_mode)) return 65;
    if (observe()) return 66;
    set_page_mode_fn setter = (set_page_mode_fn)dlsym(RTLD_DEFAULT, "posix_spawnattr_set_4k_page_size_np");
    int result = ENOSYS;
    if (setter) {
        posix_spawnattr_t attributes;
        result = posix_spawnattr_init(&attributes);
        if (!result) {
            result = setter(&attributes);
            if (!result) result = posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETEXEC);
            if (!result) {
                char **wine_argv = argv + 2;
                /* SETEXEC keeps this direct child's PID and parent. Wine receives
                 * only the runner's environment, stdin=/dev/null and owned FDs. */
                pid_t unused = 0;
                result = posix_spawn(&unused, argv[2], NULL, &attributes, wine_argv, environ);
            }
            (void)posix_spawnattr_destroy(&attributes);
        }
    }
    fprintf(stderr, "{\"record_kind\":\"pear_bootstrap_spawn_error\",\"errno\":%d}\n", result);
    return 67;
}
