# Winkey

## Introduction

Winkey was a 100 point challenge written in C where the goal was to get as close to source code as possible from just the executable. We were given the compiled executable and the assembly via the web console. Three function were present in the executable, `main`, `ctoi`, and `check`.


Ghidra decompiled `main` to the following:

```c
undefined8 main(int param_1,long param_2)

{
  int iVar1;
  undefined8 uVar2;

  if (param_1 < 2) {
    puts("No key supplied?");
    uVar2 = 0xffffffff;
  }
  else {
    iVar1 = check(*(undefined8 *)(param_2 + 8));
    if (iVar1 == -1) {
      puts("Invalid Key :(");
      uVar2 = 0xffffffff;
    }
    else {
      puts("Access Granted!");
      uVar2 = 0;
    }
  }
  return uVar2;
}
```

We got a pretty easy 18% solution essentially copying Ghidra's decompiled code. The only tricky thing were the non-existent stack variables. The dissassembly gave it away, as each block `mov`'ed -1 or 0 into $eax as opposed to storing it in a stack variable, as Ghidra suggested. `ctoi` was similarly easy just consisting of:

```c
int ctoi(char c){
  return c - 0x30;
}
```

Next came the call to `check`.
