#define _POSIX_C_SOURCE 1 /* for kill() */

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

struct who
{
    uid_t ruid;
    uid_t euid;
    uid_t suid;

    gid_t rgid;
    gid_t egid;
    gid_t sgid;
};

static struct who processes[65536];

static long poke_short(pid_t pid, long addr, short s)
{
    union { short s; long l; } w;
    w.l = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    w.s = s;
    return ptrace(PTRACE_POKEDATA, pid, addr, w.l);
}

static void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[whatever] ");
    vfprintf(stderr, fmt, ap);
    exit(1);
}

int main(int argc, char **argv)
{
    pid_t pid;

    if (argc < 2)
        die("usage: %s <program> [args]\n", argv[0]);

    pid = fork();

    if (pid < 0)
        die("%s: failed to fork()\n", argv[0]);

    if (pid == 0) {
        /* child */
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execv(argv[1], argv+1);
        die("%s: failed to execv()", argv[0]);
    } else {
        /* parent */
        waitpid(pid, NULL, 0);
        ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACEFORK|PTRACE_O_TRACEEXEC);
        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);

        while (1) {
            int status;
            pid_t trace_pid = waitpid(-1, &status, 0);

            if (trace_pid < 0) {
                kill(pid, SIGKILL);
                return 1;
            }

            if (WIFEXITED(status)) {
                if (trace_pid == pid)
                    break;

                continue;
            }

            if (WSTOPSIG(status) == (SIGTRAP|0x80)) {
                int syscall = ptrace(PTRACE_PEEKUSER, trace_pid, 8*ORIG_RAX, NULL);

                switch (syscall) {
                    case SYS_setresuid:
                    {
                        struct user_regs_struct regs;
                        ptrace(PTRACE_GETREGS, trace_pid, 0, &regs);

                        if (regs.rdi >= 0)
                            processes[trace_pid].ruid = regs.rdi;
                        if (regs.rsi >= 0)
                            processes[trace_pid].euid = regs.rsi;
                        if (regs.rdx >= 0)
                            processes[trace_pid].suid = regs.rdx;

                        ptrace(PTRACE_POKEUSER, trace_pid, 8*RAX, 0);
                        break;
                    }

                    case SYS_setresgid:
                    {
                        struct user_regs_struct regs;
                        ptrace(PTRACE_GETREGS, trace_pid, 0, &regs);

                        if (regs.rdi >= 0)
                            processes[trace_pid].rgid = regs.rdi;
                        if (regs.rsi >= 0)
                            processes[trace_pid].egid = regs.rsi;
                        if (regs.rdx >= 0)
                            processes[trace_pid].sgid = regs.rdx;

                        ptrace(PTRACE_POKEUSER, trace_pid, 8*RAX, 0);
                        break;
                    }

                    case SYS_getresuid:
                    {
                        struct user_regs_struct regs;
                        ptrace(PTRACE_GETREGS, trace_pid, 0, &regs);

                        if (regs.rdi > 0)
                            poke_short(trace_pid, regs.rdi, processes[trace_pid].ruid);

                        if (regs.rsi > 0)
                            poke_short(trace_pid, regs.rsi, processes[trace_pid].euid);

                        if (regs.rdx > 0)
                            poke_short(trace_pid, regs.rdx, processes[trace_pid].suid);

                        ptrace(PTRACE_POKEUSER, trace_pid, 8*RAX, 0);
                        break;
                    }

                    case SYS_getresgid:
                    {
                        struct user_regs_struct regs;
                        ptrace(PTRACE_GETREGS, trace_pid, 0, &regs);

                        if (regs.rdi > 0)
                            poke_short(trace_pid, regs.rdi, processes[trace_pid].rgid);

                        if (regs.rsi > 0)
                            poke_short(trace_pid, regs.rsi, processes[trace_pid].egid);

                        if (regs.rdx > 0)
                            poke_short(trace_pid, regs.rdx, processes[trace_pid].sgid);

                        ptrace(PTRACE_POKEUSER, trace_pid, 8*RAX, 0);
                        break;
                    }

                    case SYS_getuid:
                        ptrace(PTRACE_POKEUSER, trace_pid, 8*RAX, processes[trace_pid].ruid);
                        break;
                    case SYS_getgid:
                        ptrace(PTRACE_POKEUSER, trace_pid, 8*RAX, processes[trace_pid].rgid);
                        break;
                    case SYS_geteuid:
                        ptrace(PTRACE_POKEUSER, trace_pid, 8*RAX, processes[trace_pid].euid);
                        break;
                    case SYS_getegid:
                        ptrace(PTRACE_POKEUSER, trace_pid, 8*RAX, processes[trace_pid].egid);
                        break;

                    case SYS_getgroups:
                    case SYS_setgroups:
                    case SYS_chown:
                    case SYS_fchown:
                    case SYS_lchown:
                    case SYS_fchownat:
                    case SYS_setreuid:
                    case SYS_setregid:
                    case SYS_setuid:
                    case SYS_setgid:
                        ptrace(PTRACE_POKEUSER, trace_pid, 8*RAX, 0);
                    default:
                        break;
                }
            } else {
                /* fork */
                pid_t child_pid;
                ptrace(PTRACE_GETEVENTMSG, trace_pid, 0, &child_pid);
                /* blindly forcing all children to think they are root initially */
                memset(&processes[child_pid], 0, sizeof(struct who));
                ptrace(PTRACE_SETOPTIONS, child_pid, NULL, PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACEFORK|PTRACE_O_TRACEEXEC);
            }

            ptrace(PTRACE_SYSCALL, trace_pid, NULL, NULL);
        }
    }

    return 0;
}
