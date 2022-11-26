#!/bin/python3
import sys
import argparse
import os
import ctypes
import signal
from constants import *
import subprocess
import posixpath
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
    def __init__(self, bin_name):
        self.bin_name = bin_name

    def lpe_filename(line_program, file_index):
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
            for CU in dwarfinfo.iter_CUs():
                line_program = dwarfinfo.line_program_for_CU(CU)
                lp_entries = line_program.get_entries()
                for lpe in lp_entries:
                    if not lpe.state or lpe.state.file == 0:
                        continue
                    # filename = self.lpe_filename(line_program, lpe.state.file)
                    line_mapping[lpe.state.line] = lpe.state.address
            return line_mapping


class Debugger:
    def __init__(self, bin_name):
        self.bin_name = bin_name
        self.debug(f"Debugger initialized for {bin_name}")

    def lineToRIP(self, lineno):
        line_mappings = ELF(self.bin_name).get_line_mapping()
        return line_mappings.get(lineno) # ctypes.c_void_p(0x402198)

    def get_word_at(self, tracee_pid, c_pointer):
        return libc.ptrace(PTRACE_PEEKDATA, tracee_pid, ctypes.c_void_p(c_pointer), None)

    def format_word(self, word, byts = WORD_SIZE):
        raw_bytes =  word.to_bytes(byts, 'little', signed=True)
        return ' '.join(format(x, '02x') for x in raw_bytes)

    def print_n_words_around(self, tracee_pid, c_pointer, n = 4):
        for offset in range(-n*WORD_SIZE, n*WORD_SIZE+1, WORD_SIZE):
            word = self.get_word_at(tracee_pid, c_pointer + offset)
            self.debug(f"--{'>' if offset == 0 else '-'}: {self.format_word(word)}")

    def set_breakpoint(self, tracee_pid, lineno):
        address = self.lineToRIP(lineno)
        if address == None:
            self.debug("No line found")
            return

        self.debug(f"Setting breakpoint at line {lineno} -> {address}")
        low_word = self.get_word_at(tracee_pid, address)
        high_word = self.get_word_at(tracee_pid, address+WORD_SIZE)
        mask64 = np.uint64(0x00000000ffffffff)
        self.saved_word1 = np.uint64(low_word) & mask64
        self.saved_word2 = np.uint64(high_word) & mask64
        self.saved_word_combined =  int((self.saved_word2 << np.uint64(32)) | self.saved_word1)
        # litmus = np.uint64(-1)
        
        # print("context before breakpoint:")
        # self.print_n_words_around(tracee_pid, self.lineToRIP(lineno))

        libc.ptrace(PTRACE_POKEDATA, tracee_pid, ctypes.c_void_p(address), 0xCC)
        self.breakpoint_active = True

        # print("context after breakpoint:")
        # self.print_n_words_around(tracee_pid, self.lineToRIP(lineno))

        # print(f"low: {hex(self.saved_word1)}")
        # print(f"high: {hex(self.saved_word2)}")
        # print(f"mix: {hex(self.saved_word_combined)}")
        # print(f"mix converted: {hex(int(self.saved_word_combined))}")
        # print(f"litmus: {hex(litmus & mask64)}")
        # print(f"SAVED BYTES: {self.format_word(self.saved_word_combined, 8)}")
        # print(f"SAVED BYTES: {self.format_word(self.saved_word1, 8)}, {self.format_word(self.saved_word2, 8)}")


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

    def single_step(self, tracee_pid):
        libc.ptrace(PTRACE_SINGLESTEP, tracee_pid, 0, 0)
        return os.waitpid(tracee_pid, 0)[1]


    def continue_execution(self, tracee_pid):
        libc.ptrace(PTRACE_CONT, tracee_pid, 0, 0)
        return os.waitpid(tracee_pid, 0)[1]

    def remove_breakpoint(self, tracee_pid, line, registers):
        registers.rip -= 1
        libc.ptrace(PTRACE_POKEDATA, tracee_pid, self.lineToRIP(line), ctypes.c_void_p(self.saved_word_combined))
        libc.ptrace(PTRACE_SETREGS, tracee_pid, None, ctypes.byref(registers))
        self.breakpoint_active = False

    def get_tracee_exit_code(self, tracee_pid):
        # TODO: Get the exit code of process [tacee_pid].
        # process tracee_pid should have exited by now
        return 0

    def debug(self, string):
        print(f"[cs5204-debugger] > {string}")
    
    def input(self, string):
        return input(f"[cs5204-debugger] > {string}")


    def handle_signals(self, tracee_pid):
        # Main input loop of the debugger
        registers = user_regs_struct()
        self.breakpoint_active = False
        while True:
            status = self.continue_execution(tracee_pid)
            # print(f"status = {status}")
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
                self.single_step(tracee_pid)
                self.set_breakpoint(tracee_pid, self.break_line)
                continue

            # print(f"stopsig {signal.Signals(stopsig).name}")
            # print(f"openat syscall encountered, filename {self.read_string_from_pointer(tracee_pid, registers.rsi)}")
            # print(f"rip = {hex(registers.rip)} -> {hex(self.get_word_at(tracee_pid, registers.rip))}")
            if self.breakpoint_active:
                # set rip back one byte since it executed a 0xcc
                # print("context around breakpoint, before replacement")
                # self.print_n_words_around(tracee_pid, registers.rip)
                # print(f"writing: {self.saved_word_combined:x}")
                # print(f"rip = {hex(registers.rip)}")
                # print("context around breakpoint, after replacement")
                # self.print_n_words_around(tracee_pid, registers.rip)
            
                self.remove_breakpoint(tracee_pid, self.current_line, registers)
                self.debug(f"paused at line {self.current_line} -> 0x{self.lineToRIP(self.current_line):x}...")
                cmd = self.input("")
                if cmd == "c":
                    break
                elif cmd == "n":
                    self.set_breakpoint(tracee_pid, self.current_line+1)
                    self.current_line += 1
            
        self.debug(f"Tracee exited with code {self.get_tracee_exit_code(tracee_pid)}")
            

                

    def start(self, break_line):
        self.break_line = int(break_line)
        self.current_line = int(break_line)

        self.debug(f"Spawning process {self.bin_name} as tracee")
        tracee_pid = Process(self.bin_name).start()
        return self.handle_signals(tracee_pid)

        


def main(args):
    target_program = args.target
    break_line = args.breakpoint

    debugger = Debugger(target_program)
    debugger.start(break_line)


if __name__ == "__main__":
    main(setup_argparser())