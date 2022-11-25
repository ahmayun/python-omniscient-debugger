import ctypes
import sys
import os
import time

PTRACE_PEEKTEXT   = 1
PTRACE_PEEKDATA   = 2
PTRACE_POKETEXT   = 4
PTRACE_POKEDATA   = 5
PTRACE_CONT       = 7
PTRACE_SINGLESTEP = 9
PTRACE_GETREGS    = 12
PTRACE_SETREGS    = 13
PTRACE_ATTACH     = 16
PTRACE_DETACH     = 17
PTRACE_TRACEME = 0
PTRACE_SYSCALL = 24
SIGSTOP = 23
PTRACE_SETOPTIONS = 0x4200
PTRACE_O_TRACESYSGOOD = 0x00000001
libc = ctypes.CDLL('/lib/x86_64-linux-gnu/libc.so.6')


class user_regs_struct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]


registers = user_regs_struct()


def process_signals(child):
    file_to_redirect = "./ONE.txt"
    file_to_avoid = "./TWO.txt"

    while True:
        orig_file = ""

        # Wait for open syscall start 
        if wait_for_open(child) != 0:
            break

        # Find out file and re-direct if it is the target

        orig_file = read_file_name(child)

        if file_to_avoid is orig_file == 0:
            redirect_file(child, file_to_redirect)

        # Wait for open syscall exit 
        if wait_for_open(child) != 0:
            break


uniq_syscalls = {}
def wait_for_open(child):
    status, status1, status2, status3 = 0,0,0,0

    while True:
        libc.ptrace(PTRACE_SYSCALL, child, 0, 0)
        status = os.waitpid(child, 0)[1]
        # printf("Back in parent process, status: %d...\n", status);
        # Is it the open syscall (sycall number 2 in x86_64)? 
        
        status1 = os.WIFSTOPPED(status)
        status2 = os.WSTOPSIG(status)
        # print(registers)
        libc.ptrace(PTRACE_GETREGS, child, None, ctypes.byref(registers))
        # print(registers)
        # os.exit(0)
        # status3 = libc.ptrace(PTRACE_PEEKDATA, child, 15*8, None)

        # print(f"{status1} && {status2 & 0x80} && {registers.orig_rax},{registers.rax} == 257: {status1 and bool(status2 & 0x80) and (registers.orig_rax == 257)}")

        uniq_syscalls[registers.orig_rax] = True
        if status1 and bool(status2 & 0x80) and registers.orig_rax == 257:
            return 0
        if os.WIFEXITED(status):
            return 1

def read_string_from_pointer(child, c_pointer):
    chars = ""
    i = 0
    while True:
        four_chars = libc.ptrace(PTRACE_PEEKTEXT, child, ctypes.c_void_p(c_pointer + i), None).to_bytes(4, 'little').decode("utf-8")
        if '\0' in four_chars:
            return chars + four_chars.split('\0')[0]
        chars += four_chars
        i += 4

def read_file_name(child):
    # get filename string from child's text segment (address in rsi register i.e. use peekuser) and return it
    libc.ptrace(PTRACE_GETREGS, child, None, ctypes.byref(registers))
    filename = read_string_from_pointer(child, registers.rsi)
    print(f"REGISTERS: RSI = {registers.rsi} FILENAME: {filename}")
    return filename

# def redirect_file(pid_t child, const char *file):
#     printf("Redirecting file: %s\n", file);
#     char *stack_addr, *file_addr;

#     stack_addr = (char *) ptrace(PTRACE_PEEKUSER, child, sizeof(long)*RSP, 0);
#     /* Move further of red zone and make sure we have space for the file name */
#     stack_addr -= 128 + PATH_MAX;
#     file_addr = stack_addr;

#     /* Write new file in lower part of the stack */
#     do {
#         int i;
#         char val[sizeof (long)];

#         for (i = 0; i < sizeof (long); ++i, ++file) {
#             val[i] = *file;
#             if (*file == '\0') break;
#         }

#         ptrace(PTRACE_POKETEXT, child, stack_addr, *(long *) val);
#         stack_addr += sizeof (long);
#     } while (*file);

#     /* Change argument to open */
#     ptrace(PTRACE_POKEUSER, child, sizeof(long)*RSI, file_addr);

def main():
    pid = os.fork()

    if pid == 0:
        libc.ptrace(PTRACE_TRACEME, 0, 0, 0)
        libc.kill(os.getpid(), SIGSTOP)
        os.execvp(sys.argv[1], sys.argv[1:])
    else:
        status_encoded = os.waitpid(pid, 0)[1]
        libc.ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD)
        process_signals(pid)

if __name__ == "__main__":
    main()
    ls = [k for k in uniq_syscalls]
    ls.sort()
    print(ls)


# libc = ctypes.CDLL('/lib/x86_64-linux-gnu/libc.so.6') # Your libc location may vary!
# libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
# libc.ptrace.restype = ctypes.c_uint64

# libc.ptrace(PTRACE_ATTACH, pid, None, None)

# stat = os.waitpid(pid, 0)
# if os.WIFSTOPPED(stat[1]):
#     if os.WSTOPSIG(stat[1]) == 19:
#         print "we attached!"
#     else:
#         print "stopped for some other signal??", os.WSTOPSIG(stat[1])
#         sys.exit(1)