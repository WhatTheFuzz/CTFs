import re
from pwn import *

def main():
    '''Return the flag.'''
    with open('./e0d553d058fb20771200122270a068d0.txt', 'r') as f:
        lines = f.readlines()
        # For the width of the columns.
        for i in range(0, len(lines[0])):
            col = ''
            for line in lines:
                try:
                    # Transpose the columns.
                    col += line[i]
                except IndexError:
                    pass

            # Search for the flag.
            if flag:=re.search(r'flag{.*}', col):
                flag = flag.group(0)
                log.success(f'The flag is: {flag}')
                return flag
    log.error('No flag found')
    return

if __name__ == '__main__':
    main()