# Gogo

## Introduction

The problem is 110 reversing engineering challenge from picoCTF. The description states:

> mmm this is a weird file... enter_password. There is a instance of the service running at `mercury.picoctf.net:35862`.

## Information Gathering

### Hint #1

> use go tool objdump or ghidra

Then that's what we will do!

### Dynamic Analysis

861836f13e3d627dfa375bdb8389214e

After printing 'Enter Password: ', it prompts for user input. Nothing is printed after. Looks pretty straight forward.

```shell
$ ./enter_password
Enter Password: test
```

### Static Analysis

We opened the program in Binary Ninja and found a function `main.checkPassword`. It set up a string, `passwd` on the stack and passed it in to a subroutine with a string from the string table, `hardcoded`.

```c
char const passwd[0x21]
sub_8090b18(0, &passwd)
passwd[0].d = '8618'  // 861836f13e3d627dfa375bdb8389214e
passwd[4].d = '36f1'
passwd[8].d = '3e3d'
passwd[0xc].d = '627d'
passwd[0x10].d = 'fa37'
passwd[0x14].d = '5bdb'
passwd[0x18].d = '8389'
passwd[0x1c].d = '214e'
sub_8090fe0(&hardcoded, &passwd[32])
```

The rest of the function seemed to `xor` the two strings together.

```c
int32_t eax = 0
int32_t ebx = 0
while (eax s< 32)
    if (eax u< arg2)
        uint32_t ebp_1 = zx.d(*(arg1 + eax))
        if (eax u< 32 && (ebp_1 ^ zx.d(passwd[eax])).b == passwd[32 + eax])
            nop
    runtime.panicindex()
    noreturn
if (ebx != 32)
    arg_c = 0
    return eax
arg_c = 1
return eax
```