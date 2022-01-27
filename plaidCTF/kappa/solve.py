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

exe = ELF("./kappa")
hook = ELF("./hook.so")

context.binary = exe
context.log_level = 'debug'
context.terminal = ['gnome-terminal', '-e']

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

def conn():
    '''Establish the connection to the process, local or remote.
    '''

    if args.get('REMOTE'):
        io = remote('addr', 4141)

    else:
        # LD_PRELOAD to prevent `sleep` from being called.
        io = process([exe.path], env = {'LD_PRELOAD': hook.path})

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
    line = io.recvuntil(('appears!'.encode(),
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
    io.sendline(str(command.value).encode())

def main():
    '''Return the flag.
    '''

    with conn() as io:

        catch_pokemon(io, Pokemon.CHARIZARD)

        io.interactive()


if __name__ == '__main__':
    main()
