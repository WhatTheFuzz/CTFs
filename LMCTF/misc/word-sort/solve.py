#!/usr/bin/env python3

'''
WhatTheFuzz's submission for the LMCTF2022 challenge Word Sort.

Returns:
    The words in the correct order.
'''


def main():
    '''Return the flag.
    '''

    with open('words.txt') as f:
        lines = f.readlines()

    dict = {}
    for line in lines:
        # Split on colon.
        line = line.split(':')
        dict[int(line[0])] = line[1].strip()

    for key, value in sorted(dict.items()):
        print(value)

    print(dict)


if __name__ == '__main__':
    main()
