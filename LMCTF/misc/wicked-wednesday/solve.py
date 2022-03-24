#!/usr/bin/env python3

'''
WhatTheFuzz's submission for the LMCTF2022 challenge wicked-wednesday.

Returns:
    The flag to solve the challenge.
'''

import datetime

def main():
    '''Return the flag.
    '''

    num_wednesdays = 0

    for year in range(1901, 2001):
        for month in range(1, 13):
            dt = datetime.datetime(year, month, 29)



if __name__ == '__main__':
    main()
