# The More the Merrier

## Introduction

This challenge is a 75 point reversing challenge from [247CTF][247CTF].

The description states:

> One byte is great. But what if you need more? Can you find the flag hidden in
> this binary?

## Information Gathering

### Static Analysis

```shell
$ checksec ./the_more_the_merrier
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

When we look at `main` in Binary Ninja, we see the following:

```
int32_t main(int32_t argc, char** argv, char** envp){
    void* const var_10 = "247CTF{6df215eb3cc73407267031a15…"
    puts(str: "Nothing to see here..")
    return 0
}
```

The function allocated a constant string on the stack but never actually uses
it. Fortunately, it looked like a flag. We can get the string using radare2.

```python
r = r2pipe.open(exe.path)
data = r.cmd('iz')
flag = re.search(r'247CTF\{.*}', data).group(0)
```

## Solution

The previous snippet yields the flag `247CTF{6df215eb3cc73407267031a15b0ab36c}`.

[247CTF]: https://247ctf.com/
