#include <seccomp.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <linux/sched.h>
#include <stdlib.h>
#include <stdio.h>

#define ALLOW_RULE(call) { if (seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS(call), 0) < 0) { fprintf(stderr, "error at %d", __LINE__); goto out; } }
#define ERRNO_RULE(call) { if (seccomp_rule_add (ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(call), 0) < 0) { fprintf(stderr, "error at %d", __LINE__); goto out; } }
#define ADD_RULE(action, call, ...) { if (seccomp_rule_add (ctx, action, SCMP_SYS(call), __VA_ARGS__) < 0) { fprintf(stderr, "error at %d", __LINE__); goto out; } }

int main(int argc, char *argv[])
{
    int rc = -1;
    scmp_filter_ctx ctx;
    int filter_fd;

    ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
    if (ctx == NULL)
      goto out;

    /* start of syscall filter list */

    // Whitelist from zathura source code
    ALLOW_RULE (access);
    ALLOW_RULE (brk);
    ALLOW_RULE (clock_gettime);
    ALLOW_RULE (close);
    ALLOW_RULE (epoll_create1);
    ALLOW_RULE (epoll_ctl);
    ALLOW_RULE (eventfd2);
    ALLOW_RULE (exit);
    ALLOW_RULE (exit_group);
    ALLOW_RULE (fallocate);
    ALLOW_RULE (fcntl);
    ALLOW_RULE (fstat);
    ALLOW_RULE (fstatfs);
    ALLOW_RULE (ftruncate);
    ALLOW_RULE (futex);
    ALLOW_RULE (getdents64);
    ALLOW_RULE (getegid);
    ALLOW_RULE (geteuid);
    ALLOW_RULE (getgid);
    ALLOW_RULE (getpid);
    ALLOW_RULE (getppid);
    ALLOW_RULE (gettid);
    ALLOW_RULE (gettimeofday);
    ALLOW_RULE (getuid);
    ALLOW_RULE (getrandom);
    ALLOW_RULE (inotify_add_watch);
    ALLOW_RULE (inotify_init1);
    ALLOW_RULE (inotify_rm_watch);
    ALLOW_RULE (lseek);
    ALLOW_RULE (madvise);
    ALLOW_RULE (memfd_create);
    ALLOW_RULE (mmap);
    ALLOW_RULE (mremap);
    ALLOW_RULE (munmap);
    ALLOW_RULE (newfstatat);
    ALLOW_RULE (pipe2);
    ALLOW_RULE (poll);
    ALLOW_RULE (ppoll);
    ALLOW_RULE (pread64);
    ALLOW_RULE (read);
    ALLOW_RULE (readlink);
    ALLOW_RULE (recvmsg);
    ALLOW_RULE (restart_syscall);
    ALLOW_RULE (rseq);
    ALLOW_RULE (rt_sigaction);
    ALLOW_RULE (rt_sigprocmask);
    ALLOW_RULE (rt_sigreturn);
    ALLOW_RULE (set_robust_list);
    ALLOW_RULE (statx);
    ALLOW_RULE (statfs);
    ALLOW_RULE (sysinfo);
    ALLOW_RULE (write);

    ADD_RULE (SCMP_ACT_ALLOW, socket, 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_UNIX));
    ADD_RULE (SCMP_ACT_ALLOW, clone, 1, SCMP_CMP(0, SCMP_CMP_EQ, CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID));
    ADD_RULE (SCMP_ACT_ALLOW, ioctl, 1, SCMP_CMP(0, SCMP_CMP_EQ, 1));
    ADD_RULE (SCMP_ACT_ALLOW, ioctl, 1, SCMP_CMP(0, SCMP_CMP_EQ, 2));
    ADD_RULE (SCMP_ACT_ALLOW, prctl, 1, SCMP_CMP(0, SCMP_CMP_EQ, PR_SET_NAME));
    ADD_RULE (SCMP_ACT_ALLOW, prctl, 1, SCMP_CMP(0, SCMP_CMP_EQ, PR_SET_PDEATHSIG));
    ADD_RULE (SCMP_ACT_ALLOW, prctl, 1, SCMP_CMP(0, SCMP_CMP_EQ, PR_CAPBSET_READ));
    ADD_RULE (SCMP_ACT_ALLOW, openat, 1, SCMP_CMP(2, SCMP_CMP_MASKED_EQ, O_WRONLY | O_RDWR, 0));
    ADD_RULE (SCMP_ACT_ERRNO(EACCES), openat, 1, SCMP_CMP(2, SCMP_CMP_MASKED_EQ, O_WRONLY, O_WRONLY));
    ADD_RULE (SCMP_ACT_ERRNO(EACCES), openat, 1, SCMP_CMP(2, SCMP_CMP_MASKED_EQ, O_RDWR, O_RDWR));
    ADD_RULE (SCMP_ACT_ALLOW, mprotect, 1, SCMP_CMP(2, SCMP_CMP_MASKED_EQ, 0, PROT_EXEC));

    // For bookmarks (sqlite)
    ALLOW_RULE (pwrite64);
    ALLOW_RULE (fdatasync);
    ALLOW_RULE (unlink);

    /* X11 specific syscalls */
      ALLOW_RULE (mkdir);
      ALLOW_RULE (setsockopt);
      ALLOW_RULE (getsockopt);
      ALLOW_RULE (getsockname);
      ALLOW_RULE (connect);
      ALLOW_RULE (umask);
      ALLOW_RULE (uname);
      ALLOW_RULE (shmat);
      ALLOW_RULE (shmctl);
      ALLOW_RULE (shmdt);
      ALLOW_RULE (shmget);
      ALLOW_RULE (recvfrom);
      ALLOW_RULE (writev);

    /* Bwrap specific syscalls */
      ALLOW_RULE (execve);
      ALLOW_RULE (arch_prctl);
      ALLOW_RULE (set_tid_address);
      ADD_RULE (SCMP_ACT_ALLOW, prlimit64, 1, SCMP_CMP(2, SCMP_CMP_EQ, 0));
      ALLOW_RULE (getresuid);
      ALLOW_RULE (getresgid);
      ALLOW_RULE (fadvise64);
      ALLOW_RULE (sched_getaffinity);
      ADD_RULE (SCMP_ACT_ALLOW, seccomp, 1, SCMP_CMP(0, SCMP_CMP_EQ, SECCOMP_SET_MODE_FILTER));

    // Fallbacks
    ERRNO_RULE(getpeername);
    ERRNO_RULE(clone3);
    ERRNO_RULE(openat2);
    ERRNO_RULE(pwritev2);

    ERRNO_RULE(fchmodat2);
    ERRNO_RULE(map_shadow_stack);

    /* end of syscall filter list */

    filter_fd = open("seccomp_zathura_filter.bpf", O_CREAT | O_WRONLY, 0644);
    if (filter_fd == -1) {
        rc = -errno;
        goto out;
    }

    rc = seccomp_export_bpf(ctx, filter_fd);
    if (rc < 0) {
        close(filter_fd);
        goto out;
    }
    close(filter_fd);


 out:
    seccomp_release(ctx);
    return -rc;
}
