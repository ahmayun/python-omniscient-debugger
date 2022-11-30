#!/bin/python3
import sys
import argparse
import os
import ctypes
import signal
from constants import *
import subprocess
import posixpath
from copy import copy
import numpy as np
from elftools.elf.elffile import ELFFile

libc = ctypes.CDLL('/lib/x86_64-linux-gnu/libc.so.6')

def setup_argparser():
    parser = argparse.ArgumentParser()

    parser.add_argument("-t", "--target", help="specify target program")
    parser.add_argument("-b", "--breakpoint", help="line number to insert breakpoint on")

    return parser.parse_args()


class Process:
    def __init__(self, bin_name):
        self.bin_name = bin_name
    
    def start(self):
        pid = os.fork()

        if pid == 0:
            libc.ptrace(PTRACE_TRACEME, 0, 0, 0)
            libc.kill(os.getpid(), SIGSTOP)
            os.execvp(self.bin_name, ["./TWO.txt"])
        else:
            os.waitpid(pid, 0)[1]
            libc.ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL)
        return pid

class ELF:
    def __init__(self, pyfile, bin_name):
        self.bin_name = bin_name
        self.pyfile = pyfile

    def lpe_filename(self, line_program, file_index):
        lp_header = line_program.header
        file_entries = lp_header["file_entry"]

        file_entry = file_entries[file_index - 1]
        dir_index = file_entry["dir_index"]

        if dir_index == 0:
            return file_entry.name.decode()

        directory = lp_header["include_directory"][dir_index - 1]
        return posixpath.join(directory, file_entry.name).decode()

    def get_line_mapping(self):
        with open(self.bin_name, 'rb') as f: 
            self.elf = ELFFile(f)
            dwarfinfo = self.elf.get_dwarf_info()
            line_mapping = {} # {linenumber: address}
            check = {}
            for CU in dwarfinfo.iter_CUs():
                line_program = dwarfinfo.line_program_for_CU(CU)
                lp_entries = line_program.get_entries()
                for lpe in lp_entries:
                    if not lpe.state or lpe.state.file == 0:
                        continue

                    line_mapping[lpe.state.line] = lpe.state.address
            
            return line_mapping


class Debugger:
    def __init__(self, pyfile, bin_name):
        self.bin_name = bin_name
        self.pyfile = pyfile
        self.line_mappings = ELF(self.pyfile, self.bin_name).get_line_mapping()
        self.prev_line = []
        self.snapshots = []
        self.back_step = 0
        self.debug(f"Debugger initialized for {bin_name}")

    def lineToRIP(self, lineno):
        return self.line_mappings.get(lineno) # ctypes.c_void_p(0x402198)

    def get_word_at(self, tracee_pid, c_pointer):
        return libc.ptrace(PTRACE_PEEKDATA, tracee_pid, ctypes.c_void_p(c_pointer), None)

    def format_word(self, word, byts = WORD_SIZE):
        raw_bytes =  word.to_bytes(byts, 'little', signed=True)
        return ' '.join(format(x, '02x') for x in raw_bytes)

    def print_n_words_around(self, tracee_pid, c_pointer, n = 4):
        for offset in range(-n*WORD_SIZE, n*WORD_SIZE+1, WORD_SIZE):
            word = self.get_word_at(tracee_pid, c_pointer + offset)
            self.debug(f"--{'>' if offset == 0 else '-'}: {self.format_word(word)}")

    def get_double_word_at(self, tracee_pid, address):
        low_word = self.get_word_at(tracee_pid, address)
        high_word = self.get_word_at(tracee_pid, address+WORD_SIZE)
        mask64 = np.uint64(0x00000000ffffffff)
        word1 = np.uint64(low_word) & mask64
        word2 = np.uint64(high_word) & mask64
        return int((word2 << np.uint64(32)) | word1)

    def set_breakpoint(self, tracee_pid, lineno):
        i = 0
        address = 0

        self.debug(f"checking for line {lineno}")
        address = self.lineToRIP(lineno)
        if address == None:
            self.debug("No line found")
            return self.current_line

        self.debug(f"Setting breakpoint at line {lineno} -> 0x{address:x}")
        self.saved_word_combined = self.get_double_word_at(tracee_pid, address)

        libc.ptrace(PTRACE_POKEDATA, tracee_pid, ctypes.c_void_p(address), 0xCC)
        self.breakpoint_active = True
        return lineno + i

    def read_string_from_pointer(self, child, c_pointer):
        chars = bytes()
        i = 0
        while True:
            word_int = libc.ptrace(PTRACE_PEEKTEXT, child, ctypes.c_void_p(c_pointer + i), None)
            word_bytes = word_int.to_bytes(WORD_SIZE, 'little', signed=True)
            if b'\x00' in word_bytes:
                return (chars + word_bytes.split(b'\x00')[0]).decode('utf-8')
            chars += word_bytes
            i += 4

    def single_asm_step(self, tracee_pid):
        libc.ptrace(PTRACE_SINGLESTEP, tracee_pid, 0, 0)
        return os.waitpid(tracee_pid, 0)[1]


    def continue_execution(self, tracee_pid):
        libc.ptrace(PTRACE_CONT, tracee_pid, 0, 0)
        return os.waitpid(tracee_pid, 0)[1]

    def write_double_word(self, tracee_pid, address, double_word):
        libc.ptrace(PTRACE_POKEDATA, tracee_pid, address, ctypes.c_void_p(double_word))

    def set_registers(self, tracee_pid, registers):
        libc.ptrace(PTRACE_SETREGS, tracee_pid, None, ctypes.byref(registers))

    def remove_breakpoint(self, tracee_pid, line, registers):
        registers.rip -= 1
        self.write_double_word(tracee_pid, self.lineToRIP(line), self.saved_word_combined)
        self.set_registers(tracee_pid, registers)
        self.breakpoint_active = False

    def get_tracee_exit_code(self, tracee_pid):
        # TODO: Get the exit code of process [tacee_pid].
        # process tracee_pid should have exited by now
        return 0

    def debug(self, string):
        print(f"[cs5204-debugger] > {string}")
    
    def input(self, string):
        return input(f"[cs5204-debugger] > {string}")

    def single_src_step_fwd(self, tracee_pid):
        current_line = self.set_breakpoint(tracee_pid, self.current_line+1)
        self.set_current_line(current_line)
        self.back_step += 1

    def single_src_step_back(self, tracee_pid):
        current_line = self.set_breakpoint(tracee_pid, self.prev_line[-1])
        self.revert_current_line(current_line)
        self.back_step -= 1

    def revert_current_line(self, lineno):
        self.prev_line = self.prev_line[:-1]
        self.current_line = lineno

    def set_current_line(self, current_line):
        self.prev_line.append(self.current_line)
        self.current_line = current_line

    def get_stack_boundaries(self, tracee_pid, registers):
        return registers.rsp, self.stack_base

    def copy_bytes(self, tracee_pid, addr_top, addr_bottom):
        total_double_words = (addr_bottom-addr_top) // (WORD_SIZE*2)
        double_words = []
        for i in range(0, total_double_words):
            double_words.append(self.get_double_word_at(tracee_pid, addr_top + WORD_SIZE*2*i))
        return double_words
    
    def save_program_state(self, tracee_pid, registers):
        top, bottom = self.get_stack_boundaries(tracee_pid, registers)
        return copy(registers), self.copy_bytes(tracee_pid, top, bottom)

    def set_stack(self, tracee_pid, stack, stack_base_addr):
        for i, double_word in enumerate(stack):
            self.write_double_word(tracee_pid, stack_base_addr + WORD_SIZE*2*i, double_word)

    def restore_state(self, tracee_pid, state):
        registers, stack = state
        self.set_registers(tracee_pid, registers)
        self.set_stack(tracee_pid, stack, self.stack_base)

    def handle_signals(self, tracee_pid):
        # Main input loop of the debugger
        registers = user_regs_struct()
        self.breakpoint_active = False
        while True:
            status = self.continue_execution(tracee_pid)
            is_stopped = os.WIFSTOPPED(status)
            stopped_by_tracer = (os.WSTOPSIG(status) & 0x80) != 0
            stopsig = (os.WSTOPSIG(status) | 0x80) ^ 0x80
            libc.ptrace(PTRACE_GETREGS, tracee_pid, None, ctypes.byref(registers))

            if os.WIFEXITED(status):
                return 0

            if registers.orig_rax == 231: # check if exit
                continue
            
            if registers.orig_rax == 59: # execve
                # Set breakpoint after execve call completes
                self.single_asm_step(tracee_pid)
                self.stack_base = registers.rsp
                self.debug(f"stack base = 0x{self.stack_base:x}")
                self.current_line = self.set_breakpoint(tracee_pid, self.break_line)
                continue

            if self.breakpoint_active:
                self.remove_breakpoint(tracee_pid, self.current_line, registers)
                self.debug(f"paused at line {self.current_line} -> 0x{self.lineToRIP(self.current_line):x}...")
                cmd = self.input("")
                if cmd == "c":
                    break
                elif cmd == "n":
                    snapshot_regs, snapshot_stack = self.save_program_state(tracee_pid, registers)
                    self.snapshots.append((snapshot_regs, snapshot_stack))
                    self.single_src_step_fwd(tracee_pid)
                elif cmd == "b":
                    self.single_src_step_back(tracee_pid)
                    self.restore_state(tracee_pid, self.snapshots[self.back_step])
                
        self.debug(f"Tracee exited with code {self.get_tracee_exit_code(tracee_pid)}")

    def start(self, break_line):
        self.break_line = int(break_line)
        self.current_line = int(break_line)

        self.debug(f"Spawning process {self.bin_name} as tracee")
        tracee_pid = Process(self.bin_name).start()
        status = self.handle_signals(tracee_pid)
        self.debug(f"debugger exited with status {status}")
        return status

        

def cython_transpile(pyfile):
    raw_name = pyfile.split('/')[-1][:-3]

    session = subprocess.Popen(['sh', './python_to_elf.sh', raw_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    session.communicate()
    
    if session.returncode != 0:
        raise Exception("could not compile python to elf")

    return f'bin/{raw_name}'


def main(args):
    file = args.target
    target_program = cython_transpile(file) if file.endswith(".py") else file
    break_line = args.breakpoint

    debugger = Debugger(file, target_program)
    debugger.start(break_line)


if __name__ == "__main__":
    main(setup_argparser())