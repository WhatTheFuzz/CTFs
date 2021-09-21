# Easy as GDB

## Introduction

This was a 2021 challenge for picoCTF for Reverse Engineering worth 250 points. I originally sought out this challenge to hone my [angr][angr] API skills. To that end, I found [ret2basic's][ret] writeup that went over how to solve it with angr. I would recommend taking a look, as he or she explains it really well.

The description states:
> The flag has got to be checked somewhere...

We are given the executable itself.

## Information Gathering

### Hint #1

> <https://sourceware.org/gdb/onlinedocs/gdb/Basic-Python.html#Basic-Python>

The hint directs us how to invoke gdb command sfrom within Python. Fortunately, `pwntools` makes this really easy for us. Also we are going to ignore this hint and solve the problem with [angr][angr].

### Hint #2

> With GDB Python, I can guess wrong flags faster than ever before!

This hint, along with the filename of `brute` might be trying to tell us something...Fortunately, we can let angr do the heavy lifting.

### Vulnerability Mitigations

```shell
$ checksec brute
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

This shouldn't really matter for this challenge, but good to know anyway.

## Static Analysis

Let's start with `main`.

```c
int main(void)

{
  char *user_buf;
  size_t len;
  undefined4 uVar1;
  int is_correct;

  user_buf = (char *)calloc(0x200,1);
  printf("input the flag: ");
  fgets(user_buf,0x200,stdin);
  len = strnlen(s_z.nh_e_|mCo6eb@_Cb@?X_X3bkS08_00002008,0x200);
  uVar1 = loop(user_buf,len);
  FUN_000007c2(uVar1,len,1);
  is_correct = check_flag(uVar1,len);
  if (is_correct == 1) {
    puts("Correct!");
  }
  else {
    puts("Incorrect.");
  }
  return 0;
}
```

`main` reads in 0x200 bytes from `stdin` via `fgets`. It then gets the length of a hardcoded string that can be no longer than 0x200. `main` then passes the user input and size of the hard-coded string to what we will call `loop`.

```c
char * loop(char *user_input,uint len)

{
  size_t __n;
  char *__dest;
  undefined4 uVar1;
  uint local_1c;

  uVar1 = 0x837;
  __n = (len & 0xfffffffc) + 4;
  __dest = (char *)malloc((len & 0xfffffffc) + 5);
  strncpy(__dest,user_input,__n);
  local_1c = 0xabcf00d;
  while (local_1c < 0xdeadbeef) {
    transform(__dest,__n,local_1c,uVar1);
    local_1c = local_1c + 0x1fab4d;
  }
  return __dest;
}
```

`loop` will create a dynamic buffer in the heap that is the size of the hardcoded string from `main`. We then `strncpy` the user input into our dynamic buffer but limit the size to the length of the hardcoded string. Interesting, so maybe not all our user input is making its way to the rest of the program. `loop` then chooses some interesting start (0xabcf00d) and ending (0xdeadbeef) values to loop over input and pass it to `transform`. `transform` does a lot of bit shifting so I really do not care to piece it together statically. Let's return to `main`. Notice that there is a check that `puts` 'Correct!' or 'Incorrect' to stdout.

Hmm. So we will give the program some input, it looks to transform it and check it against a computed value. I am currently thinking we can tell angr how to start the program and to explore and reach our correct statement while avoiding the incorrect one.

### Dynamic Analysis



[ret]: https://www.ctfwriteup.com/picoctf/picoctf-2021/picoctf-2021-reverse-engineering
[angr]: https://angr.io/
