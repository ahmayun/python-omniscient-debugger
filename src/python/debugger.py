#!/bin/python3
import sys
import argparse
import os
import ctypes
import signal
from constants import *
import subprocess
import numpy as np

libc = ctypes.CDLL('/lib/x86_64-linux-gnu/libc.so.6')

def setup_argparser():
    parser = argparse.ArgumentParser()

    parser.add_argument("-t", "--target", help="specify target program")
    parser.add_argument("-b", "--breakpoint", help="line number to insert breakpoint on")

    return parser.parse_args()


class Process:
    def __init__(self, filename):
        self.filename = filename
        print(f"Initializing process for {filename}")
    
    def start(self):
        print(f"Starting process {self.filename} as tracee")
        pid = os.fork()

        if pid == 0:
            libc.ptrace(PTRACE_TRACEME, 0, 0, 0)
            libc.kill(os.getpid(), SIGSTOP)
            os.execvp(self.filename, ["./TWO.txt"])
        else:
            os.waitpid(pid, 0)[1]
            libc.ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL)
        return pid

    def has_exited(self):
        return True

    def exit_code(self):
        return 0


class Debugger:
    def __init__(self, filename):
        self.filename = filename
        print(f"Debugger initialized for {filename}")

    def lineToRIP(self, lineno):
        return 0x401d0d # ctypes.c_void_p(0x402198)

    def get_word_at(self, tracee_pid, c_pointer):
        return libc.ptrace(PTRACE_PEEKDATA, tracee_pid, ctypes.c_void_p(c_pointer), None)

    def format_word(self, word, byts = WORD_SIZE):
        raw_bytes =  word.to_bytes(byts, 'little', signed=True)
        return ' '.join(format(x, '02x') for x in raw_bytes)

    def print_n_words_around(self, tracee_pid, c_pointer, n = 4):
        for offset in range(-n*WORD_SIZE, n*WORD_SIZE+1, WORD_SIZE):
            word = self.get_word_at(tracee_pid, c_pointer + offset)
            print(f"--{'>' if offset == 0 else '-'}: {self.format_word(word)}")

    def set_breakpoint(self, tracee_pid, lineno):
        print(f"Setting breakpoint at line {lineno}")
        low_word = self.get_word_at(tracee_pid, self.lineToRIP(lineno))
        high_word = self.get_word_at(tracee_pid, self.lineToRIP(lineno)+WORD_SIZE)
        mask64 = np.uint64(0x00000000ffffffff)
        self.saved_word1 = np.uint64(low_word) & mask64
        self.saved_word2 = np.uint64(high_word) & mask64
        # litmus = np.uint64(-1)
        self.saved_word_combined =  int((self.saved_word2 << np.uint64(32)) | self.saved_word1)
        
        print("context before breakpoint:")
        self.print_n_words_around(tracee_pid, self.lineToRIP(lineno))

        libc.ptrace(PTRACE_POKEDATA, tracee_pid, ctypes.c_void_p(self.lineToRIP(lineno)), 0xCC)

        print("context after breakpoint:")
        self.print_n_words_around(tracee_pid, self.lineToRIP(lineno))

        # print(f"low: {hex(self.saved_word1)}")
        # print(f"high: {hex(self.saved_word2)}")
        # print(f"mix: {hex(self.saved_word_combined)}")
        # print(f"mix converted: {hex(int(self.saved_word_combined))}")
        # print(f"litmus: {hex(litmus & mask64)}")
        # print(f"SAVED BYTES: {self.format_word(self.saved_word_combined, 8)}")
        # print(f"SAVED BYTES: {self.format_word(self.saved_word1, 8)}, {self.format_word(self.saved_word2, 8)}")
    
    def step_over(self):
        pass

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

    def handle_signals(self, tracee_pid):
        # Main input loop of the debugger
        registers = user_regs_struct()
        breakpoint_set = False
        while True:
            status = self.continue_execution(tracee_pid)
            print(f"status = {status}")
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
                self.set_breakpoint(tracee_pid, 2)
                breakpoint_set = True
                continue

            # if is_stopped and not stopped_by_tracer:
                # p = subprocess.Popen(f"grep test_program /proc/{tracee_pid}/maps", stdout=subprocess.PIPE, shell=True)
                # print(p.communicate()[0].decode("utf-8"))
                # continue


            # if registers.orig_rax != 257:
            #     continue

            # print(f"openat syscall encountered, filename {self.read_string_from_pointer(tracee_pid, registers.rsi)}")
            print(f"stopsig {signal.Signals(stopsig).name}")
            print(f"rip = {hex(registers.rip)} -> {hex(self.get_word_at(tracee_pid, registers.rip))}")
            if breakpoint_set:
                # set rip back one byte since it executed a 0xcc
                registers.rip -= 1

                print("context around breakpoint, before replacement")
                self.print_n_words_around(tracee_pid, registers.rip)

                print(f"writing: {self.saved_word_combined:x}")
                libc.ptrace(PTRACE_POKEDATA, tracee_pid, self.lineToRIP(None), ctypes.c_void_p(self.saved_word_combined))
                # libc.ptrace(PTRACE_POKEDATA, tracee_pid, self.lineToRIP(None)+4, self.saved_word2)
                libc.ptrace(PTRACE_SETREGS, tracee_pid, None, ctypes.byref(registers))

                print(f"rip = {hex(registers.rip)}")
                print("context around breakpoint, after replacement")
                self.print_n_words_around(tracee_pid, registers.rip)
                
                # input("...")
                breakpoint_set = False

            # print(f"rip: {hex(registers.rip)}")
            # cmd = input()
            # if cmd is "q":
            #     return 0
                
            self.step_over()

    def start(self, break_line):
        tracee_pid = Process(self.filename).start()
        # self.set_breakpoint(tracee_pid, break_line)
        return self.handle_signals(tracee_pid)

        


def main(args):
    target_program = args.target
    break_line = args.breakpoint
    print(target_program)

    debugger = Debugger(target_program)
    exit_code = debugger.start(break_line)

    print(f"Tracee exited with code {exit_code}")


if __name__ == "__main__":
    main(setup_argparser())