#!/usr/bin/env python3
'''
WhatTheFuzz's submission for the picoCTF challenge sum-o-primes.

This script can be used in the following manner:
python3 ./solve.py
'''

import z3
import binascii
from pwn import *

context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']


def main():
    '''Return the flag.
    '''

    # Copied from output file.
    x = 0x198e800b4f9e29e69889bc7a42b92dbd764cb22dbeb5fb81b1d9778bfe8c4b85d08a7f990019d537b6856aa1ff7355d0bef66c0a5c954bb4b7e58ac094c42ac1c23d23f8f763e41bbebdfa985505ab3571f8355290d2ca66ac333c4e30f1b7354c37d67db2c13c7e07ca3b6d98283f5042a55e23796ca227f428e0d3a83057510
    n = 0xa0ab034d978fdd92e73f3f7536f4f2ff5f4dee70b5f1d319903ec65f2a8ffe729688452d2c1f25a7c330e6bb532580094196f888a20ba7556f0907d8a4884bddbde4c4361582fcf163799a0f49b9d196b32012e1b5a4dabd2a6c9e9a47173f903ae1ebe2db66ebf55471982d52e6cbeb8060dd0f01d950a30ac5a830ad2414c86f97703717752bd20abb528f7738e010a7c3e8116b2c3a6706d900d83ff4afc7ca8b47f6c19d1de00c7ea8666c617a5e33d600b381b263662ad17a5d4262a819a57b357fee702538355ee7723f9c694a3c98999bc2432658c7798119d7a54d5e4c01447c7afcdf36110be0be195cea0828b17f5e86b4702341e7a37babb3db07
    c = 0x497f4e814e3d7093d49c33c9b743748455b82496af6a8900e6d3c899b58a5e8d32fde34dccf882a87859d8508a18fe23088c8b58dd33decb3e9f4c1737c85f0b66114e62efe0da72fcee95619e4d76e7c485f161464f7067237bbcc213bd02b5e2816208333146652395e07f4245dfd654755417d35cc0a27933dd48ab219f31ed73820087c1ec7e2150caf4f5f0de052d14a2e492715e3a3ca24de41240d49494532b4d5fa54c59db08c6d94938f33a489c24a9b4a7d6b2d57164ce7aacdd0707302fded17671d197485c764064ed97d2560274b5ed4994446e8f790e16e05e8dd4b2d39e228a715f70bd012eb7eaec65e67734fad95f55be307e26b2106226

    # Copied from `gen.py`.
    e = 65537

    # Define out symbolic input.
    p, q = z3.Ints('p q')

    # Add our constraints. This is pulled from the `gen.py` script.
    s = z3.Solver()
    s.add(x == p + q, n == p * q)

    assert s.check() == z3.sat, 'Could not find a solution.'

    # Get our concrete values.
    p = s.model()[p].as_long()
    q = s.model()[q].as_long()

    log.info(f'p is: {p}')
    log.info(f'q is: {q}')

    # Calculate the flag.
    m = math.lcm(p - 1, q - 1)
    d = pow(e, -1, m)
    flag = hex(pow(c, d, n))

    flag = binascii.unhexlify(flag[2:])
    log.success(f'The flag is: {flag}')

    assert flag == b'picoCTF{ee326097}', 'The flag is incorrect.'
    return flag


if __name__ == '__main__':
    main()
