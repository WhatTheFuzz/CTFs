#!/usr/bin/env python3

"""
WhatTheFuzz's submission for the picoCTF challenge brute.

This script can be used in the following manner:
python3 ./solve.py

Returns:
    The flag to solve the challenge.
"""

from pwn import *
import claripy
import angr

exe = ELF("./brute")

context.binary = exe
context.log_level = 'info'

FLAG_LEN = 30

def getflag():
    '''Start an angr project to solve for the flag. Returns the flag before we test it on the binary.
    '''

    # Create an angr project.
    project = angr.Project('./brute',
        use_sim_procedures=True,
        main_opts={
            'arch':'i386',
            'entry_point':0x580,
            'base_addr':0x00
        }
    )

    # Specify the input the program.
    # We know it can only be up to 0x200 characters, including the new line.
    # https://www.ctfwriteup.com/picoctf/picoctf-2021/picoctf-2021-reverse-engineering
    flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(FLAG_LEN)]
    # Add the new line.
    flag = claripy.Concat( *flag_chars + [claripy.BVV(b'\n')])

    # Specify our state.
    state = project.factory.full_init_state(
        args=['brute'],
        stdin=angr.SimFile('/dev/stdin', content=flag),
        add_options=angr.options.unicorn
    )

    # Constrain characters to be printable.
    for i in flag_chars:
        state.solver.add(i >= ord('!'))
        state.solver.add(i <= ord('~'))

    # Create a simulation manager.
    find_addr  = 0x00a72 #  the address of "call puts" for SUCCESS
    avoid_addr = 0x00a86 # the address of "call puts" for FAILURE
    simgr = project.factory.simulation_manager(state)
    simgr.explore(find=find_addr, avoid=avoid_addr)

    if (len(simgr.found) > 0):
        for found in simgr.found:
            print(found.posix.dumps(0))



def conn():
    '''Establish the connection to the process, local or remote.
    '''

    r = process([exe.path])
    return r


def main():
    '''Return the flag.
    '''

    r = conn()
    #flag = getflag()
    flag = b'picoCTF{I_5D3_A11DA7_e5458cbf}\n'

    # Test the flag.
    r.send(flag)

    # Ensure that this flag works.
    data = r.recvline_containsS(b'Correct!')
    assert('Correct!' in data)
    r.close()

    log.success(f'The flag is: {flag.decode("ascii")}')
    return flag


if __name__ == "__main__":
    main()
