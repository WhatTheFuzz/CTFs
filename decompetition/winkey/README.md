# Winkey

## Introduction

Winkey was a 100 point challenge written in C where the goal was to get as close to source code as possible from just the executable. We were given the compiled executable and the assembly via the web console. The assembly below was what we needed to match:

```asm
; This is the disassembly you're trying to reproduce.
; It uses Intel syntax (mov dst, src).

check:
  endbr64
  push    rbp
  mov     rbp, rsp
  push    rbx
  sub     rsp, 0x48
  mov     [rbp-0x48], rdi
  mov     rax, fs:[0x28]
  mov     [rbp-0x18], rax
  xor     eax, eax
  mov     [rbp-0x2c], 0
  mov     [rbp-0x28], 0
  mov     [rbp-0x30], 0
  mov     [rbp-0x20], 0
  mov     [rbp-0x26], 0
  mov     [rbp-0x22], 0
  lea     rdi, [rbp-0x26]
  lea     rsi, [rbp-0x20]
  lea     rcx, [rbp-0x30]
  lea     rdx, [rbp-0x2c]
  mov     rax, [rbp-0x48]
  mov     r9, rdi
  mov     r8, rsi
  lea     rsi, [mem1]; "%5c-%3c-%7c-%5c"
  mov     rdi, rax
  mov     eax, 0
  call    __isoc99_sscanf@plt.sec
  lea     rax, [rbp-0x2c]
  mov     rdi, rax
  call    strlen@plt.sec
  cmp     rax, 5
  jne     block4
block1:
  lea     rax, [rbp-0x30]
  mov     rdi, rax
  call    strlen@plt.sec
  cmp     rax, 3
  jne     block4
block2:
  lea     rax, [rbp-0x20]
  mov     rdi, rax
  call    strlen@plt.sec
  cmp     rax, 7
  jne     block4
block3:
  lea     rax, [rbp-0x26]
  mov     rdi, rax
  call    strlen@plt.sec
  cmp     rax, 5
  je      block5
block4:
  mov     eax, 0xffffffff
  jmp     block20
block5:
  lea     rcx, [rbp-0x38]
  lea     rdx, [rbp-0x3c]
  lea     rax, [rbp-0x2c]
  lea     rsi, [mem2]; "%3d%2d"
  mov     rdi, rax
  mov     eax, 0
  call    __isoc99_sscanf@plt.sec
  mov     eax, [rbp-0x3c]
  test    eax, eax
  jle     block7
block6:
  mov     eax, [rbp-0x3c]
  cmp     eax, 0x16e
  jle     block8
block7:
  mov     eax, 0xffffffff
  jmp     block20
block8:
  mov     eax, [rbp-0x38]
  cmp     eax, 3
  jle     block11
block9:
  mov     eax, [rbp-0x38]
  cmp     eax, 0x5e
  jg      block11
block10:
  mov     eax, 0xffffffff
  jmp     block20
block11:
  lea     rax, [rbp-0x30]
  lea     rsi, [mem3]; "OEM"
  mov     rdi, rax
  call    strcmp@plt.sec
  test    eax, eax
  je      block13
block12:
  mov     eax, 0xffffffff
  jmp     block20
block13:
  movzx   eax, [rbp-0x20]
  movsx   eax, al
  mov     edi, eax
  call    ctoi
  test    eax, eax
  jne     block16
block14:
  movzx   eax, [rbp-0x19]
  movsx   eax, al
  mov     edi, eax
  call    ctoi
  test    eax, eax
  je      block16
block15:
  movzx   eax, [rbp-0x19]
  movsx   eax, al
  mov     edi, eax
  call    ctoi
  cmp     eax, 8
  jle     block17
block16:
  mov     eax, 0xffffffff
  jmp     block20
block17:
  movzx   eax, [rbp-0x1f]
  movsx   eax, al
  mov     edi, eax
  call    ctoi
  mov     ebx, eax
  movzx   eax, [rbp-0x1e]
  movsx   eax, al
  mov     edi, eax
  call    ctoi
  add     ebx, eax
  movzx   eax, [rbp-0x1d]
  movsx   eax, al
  mov     edi, eax
  call    ctoi
  add     ebx, eax
  movzx   eax, [rbp-0x1c]
  movsx   eax, al
  mov     edi, eax
  call    ctoi
  add     ebx, eax
  movzx   eax, [rbp-0x1b]
  movsx   eax, al
  mov     edi, eax
  call    ctoi
  add     ebx, eax
  movzx   eax, [rbp-0x1a]
  movsx   eax, al
  mov     edi, eax
  call    ctoi
  add     eax, ebx
  mov     [rbp-0x34], eax
  mov     edx, [rbp-0x34]
  movsxd  rax, edx
  imul    rax, rax, -0x6db6db6d
  shr     rax, 0x20
  add     eax, edx
  sar     eax, 2
  mov     ecx, eax
  mov     eax, edx
  sar     eax, 0x1f
  sub     ecx, eax
  mov     eax, ecx
  mov     ecx, eax
  shl     ecx, 3
  sub     ecx, eax
  mov     eax, edx
  sub     eax, ecx
  test    eax, eax
  je      block19
block18:
  mov     eax, 0xffffffff
  jmp     block20
block19:
  mov     eax, 0
block20:
  mov     rsi, [rbp-0x18]
  xor     rsi, fs:[0x28]
  je      block22
block21:
  call    __stack_chk_fail@plt.sec
block22:
  add     rsp, 0x48
  pop     rbx
  pop     rbp
  ret
```

Ghidra decompiled it to the following:

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

We got a pretty each 18% solution essentially copying Ghidra's decompiled code. The only tricky thing were the non-existent stack variables. The dissassembly gave it away, as each block `mov`'ed -1 or 0 into $eax as opposed to storing it in a stack variable, as Ghidra suggested. Next came the call to `check`.
