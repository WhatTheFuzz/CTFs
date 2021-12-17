# ARMssembly 0

## Introduction

> What integer does this program print with arguments 1765227561 and 1830628817?
> File: chall.S
> Flag format: picoCTF{XXXXXXXX} -> (hex, lowercase, no 0x, and 32 bits. ex. 5614267 would be picoCTF{0055aabb})

We are given the following:

* chall.S: assembly code for the challenge

## Information Gathering

### Hint #1

> Simple compare

I think this hint is directing us to look at the assembly by hand. But who wants to do that? Let's go grab a compiler.

## Strategy

We're going to cross-compile this challenge into an AARCH64 binary and get the flag from it. On Fedora, we installed the following:

```sudo dnf install gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu qemu-user-static```

We then attempted to cross-compile it with `aarch64-linux-gnu-gcc` but ran into the following error:

```
$ aarch64-linux-gnu-gcc -march=armv8-a -static ./chall.S
/usr/bin/aarch64-linux-gnu-ld: cannot find crt1.o: No such file or directory
/usr/bin/aarch64-linux-gnu-ld: cannot find crti.o: No such file or directory
/usr/bin/aarch64-linux-gnu-ld: cannot find -lc
collect2: error: ld returned 1 exit status
```

I think the loader was warning us that it could not link in libc for the `printf` and `atoi` symbols included in the challenge. I looked around in `/usr/aarch64-linux-gnu/` for libc and noticed that I actually did not have any libraries present. I grabbed some more info about the compiler with `dnf` and found that it does not currently support compiling user executables:

```
$ dnf info gcc-aarch64-linux-gnu
Name         : gcc-aarch64-linux-gnu
Version      : 11.2.1
Release      : 1.fc35
Architecture : x86_64
Size         : 94 M
Source       : cross-gcc-11.2.1-1.fc35.src.rpm
Repository   : @System
From repo    : fedora
Summary      : Cross-build binary utilities for aarch64-linux-gnu
URL          : http://gcc.gnu.org
License      : GPLv3+ and GPLv3+ with exceptions and GPLv2+ with exceptions and LGPLv2+ and BSD
Description  : Cross-build GNU C compiler.
             :
             : Only building kernels is currently supported.  Support for cross-building
             : user space programs is not currently provided as that would massively multiply
             : the number of packages.
```

I've never seen this on my Ubuntu box and tried it out in a container. Sure enough, it worked. So if you're on Ubuntu, you can probably run the previously mentioned commands to get the flag. Otherwise, checkout out the Dockerfile that will compile it and run it. The `solve.py` script will build the container for you, run it, parse the output, and report the flag.

## Solution

As long as you have `docker` installed (both the package and the Python library), you can run the following command to solve the challenge:

```shell
$ ./solve.py
[+] Result: 1830628817
[+] The flag is: picoCTF{6d1d2dd1}
[+] Time: 17.26059579849243
```

Note that it takes awhile the first time if you don't have a cached image. In the above example it took 17 seconds. After it's been created and cached, the solution time will be much faster.
