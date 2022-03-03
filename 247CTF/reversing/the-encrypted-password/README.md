# The Encrypted Password

## Introduction

This challenge is a 115 point reversing problem. The description states:

> You won't find the admin's secret password in this binary. We even encrypted
> it with a secure one-time-pad. Can you still recover the password?

## Information Gathering

We do not have any hints for this problem.

### Dynamic Analysis

When we run the program we get the following before the program exits:

```sh
$ ./encrypted_password
Enter the secret password:
hello world
```

Not information to gather here, let's look at it with Binary Ninja.

### Static Analysis

```shell
checksec ./encrypted_password
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

The decompiled C looks a bit like this:

```c
int32_t main(int32_t argc, char** argv, char** envp)

{
    void* fsbase;
    int64_t rax = *(int64_t*)((char*)fsbase + 0x28);
    int64_t var_a8 = 0x3930343965353738;
    int64_t var_a0 = 0x3861623131383966;
    int64_t var_98 = 0x3665656562303635;
    int64_t var_90 = 0x3264373763306266;
    char var_88 = 0;
    int64_t var_78 = 0x5a53010106040309;
    int64_t var_70 = 0x5c585354500a5b00;
    int64_t var_68 = 0x555157570108520d;
    int64_t var_60 = 0x5707530453040752;
    char var_58 = 0;
    int32_t var_b0 = 0;
    while (true)
    {
        if (((int64_t)var_b0) >= strlen(&var_a8))
        {
            break;
        }
        *(int8_t*)(&var_78 + ((int64_t)var_b0)) = (*(int8_t*)(&var_78 + ((int64_t)var_b0)) ^ *(int8_t*)(&var_a8 + ((int64_t)var_b0)));
        var_b0 = (var_b0 + 1);
    }
    puts("Enter the secret password:");
    void var_48;
    fgets(&var_48, 0x21, stdin);
    if (strcmp(&var_48, &var_78) == 0)
    {
        printf("You found the flag!\n247CTF{%s}\n", &var_78);
    }
    int32_t var_ac = 0;
    while (true)
    {
        if (((int64_t)var_ac) >= strlen(&var_a8))
        {
            break;
        }
        *(int8_t*)(&var_78 + ((int64_t)var_ac)) = 0;
        var_ac = (var_ac + 1);
    }
    if ((rax ^ *(int64_t*)((char*)fsbase + 0x28)) == 0)
    {
        return 0;
    }
    __stack_chk_fail();
    /* no return */
}
```

It looks like we can just use a debugger and break on `strcmp` and see what the password is being compared to. This does indeed work, but there is a gotcha.

### Back to Dynamic Analysis

If we set a breakpoint on `strcmp`, we hit it a bunch of times because the dynamic linker uses it to link in our libraries. This isn't what we want. We want to break on the specific time `strcmp` is called within `main`. `main` isn't a defined symbol and the program is position independent, so we can't just break on an address. The solution is that we break on `strcmp@plt` which will contain the address that our function has for `strcmp` (pointing to the GOT) before it has been resolved by the dynamic linker. This will instantly illuminate the password if we check out the arguments $rdi and $rsi (this is amd64, so those are the arguments used for fastcalls).

In the GDB output below, we see that our input in $rdi, `test`, is compared to $rsi, `141c85ccfb2ae19d8d8c224c4e403dce`. The latter is the password. Let's try it:

```sh
$ ./encrypted_password
Enter the secret password:
141c85ccfb2ae19d8d8c224c4e403dce
You found the flag!
247CTF{141c85ccfb2ae19d8d8c224c4e403dce}
```
