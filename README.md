# CTF Writeups

Hey there, I'm Sean and I enjoy doing CTF problems in my spare time. My current
position has me doing a lot of binary exploitation and software reverse
engineering so I tend to focus on those categories. Most writeups that I see
online suck and I hope these do a better job explaining some of the fundamental
concepts.

In all of my solutions I try my best to include a reproducible solution written
with pwntools. It's not about the flags, but about the journey that got us the
flag.

Hopefully this doesn't age like milk, but I've also tried to do some video
walkthroughs of some of these CTF problems. You can view them on
[YouTube][youtube].

The following is a list of common Unix Access topics and the CTF challenges
that relate to them.

## Unix Access Knowledge

### Vulnerability Classes

#### Describe the concepts and terms associated with vulnerability classes

* Stack buffer overflow: [clutter-overflow][clutter-overflow]
* Heap buffer overflow: [unsubscriptions-are-free][unsubscriptions]
* Use-after-free (UAF): [cache-me-outside][cache-me-outside],
[are-you-root][are-you-root]
* How the heap grooming can be used during heap overflow and UAF exploitation:
[are-you-root][are-you-root]
* How uninitialized variables can be used for exploitation:
[are-you-root][are-you-root]
* How race conditions can be used in exploitation
* How data type confusion
* How format string vulnerabilities can be used for arbitrary read/write
primitive: [stonks][stonks], [got_hax][got_hax]

#### Demonstrate the ability to exploit vulnerability classes

* Write working shellcode from scratch and show all steps to write the
shellcode: [level-0][level-0], [level-1][level-1]
* Stack buffer overflow with and without the following mitigations: address
space layout randomization (ASLR), Non-eXecutable memory (NX), and stack
canaries: [clutter-overflow][clutter-overflow], [heres-a-libc][heres-a-libc]
* Heap buffer overflow using heap grooming and objects with function pointers:
[are-you-root][are-you-root]
* Heap buffer overflow by corrupting heap data structures:
[unsubscriptions-are-free][unsubscriptions]
* UAF with objects containing function pointers: [are-you-root][are-you-root]
* UAF with objects that allow an arbitrary read/write primitive:
[cache-me-outside][cache-me-outside]
* Data type confusion vulnerabilities
* Format string vulnerabilities for arbitrary read/write primitive:
[stonks][stonks], [got_hax][got_hax]

#### Describe the purpose and use of exploitation primitives

* Arbitrary write primitive: [got_hax][got_hax]
* Relative write primitive: [cache-me-outside][cache-me-outside]
* Arbitrary read primitive: [got_hax][got_hax]
* How primitives can be chained to build an exploit
* How a write primitive can be used to escalate privileges/execute arbitrary
code: [got_hax][got_hax]

#### Demonstrate the ability to implement exploitation primitives

* Arbitrary write primitive: [got_hax][got_hax]
* Relative write primitive: [cache-me-outside][cache-me-outside]
* Arbitrary read primitive: [got_hax][got_hax]
* How primitives can be chained to build an exploit
* How a write primitive can be used to escalate privileges/execute arbitrary
code: [got_hax][got_hax]

#### Describe the purpose and structure of the following ELF linking structures and how they can be abused in binary exploitation

* Procedural Linkage Table: [got_hax][got_hax]
* Global Offset Table: [got_hax][got_hax]

#### Describe the following dynamic relocation modes in terms of PLT/GOT data structure interaction, and how exploitation primitives differ between them

* Partial RELRO: [got_hax][got_hax]
* Full RELRO: [got_hax][got_hax]

#### Describe the purpose and use of return oriented programming (ROP)/jump oriented programming (JOP)

* How can ROP/JOP be used to evade ASLR/NX: [heres-a-libc][heres-a-libc],
[guessing-game-1][guessing-game-1]
* Common methods and tools to find ROP/JOP gadgets:
[heres-a-libc][heres-a-libc], [guessing-game-1][guessing-game-1]
* How can ROP/JOP be used to call libc functions/sys calls:
[heres-a-libc][heres-a-libc], [guessing-game-1][guessing-game-1]
* How can ROP/JOP be used to chain gadgets to execute code:
[guessing-game-1][guessing-game-1]
* How can ROP/JOP be used to execute arbitrary shellcode

#### Demonstrate the ability to implement ROP/JOP to

* Find ROP/JOP gadgets: [guessing-game-1][guessing-game-1]
* Call libc functions and system calls: [heres-a-libc][heres-a-libc],
[guessing-game-1][guessing-game-1]
* Chain gadgets to execute code: [guessing-game-1][guessing-game-1]
* Execute arbitrary shellcode

#### Describe the purpose and implementation of exploitation mitigations

* ASLR
* Data Execution Prevention (DEP)/NX: [heres-a-libc][heres-a-libc],
[guessing-game-1][guessing-game-1]
* Position Independent Executables (PIEs)
* How PIEs affect exploitation
* Stack canaries: [guessing-game-1]
* Safe list unlinking

### Software Reverse Engineering

#### Compare and contrast techniques and use cases of

* Static reverse engineering
* Dynamic reverse engineering: [heres-a-libc][heres-a-libc]

#### Demonstrate familiarity in using the following types of tools to perform static and dynamic reverse engineering

* Static disassemblers
* Debuggers
* Automation techniques using above tools

#### Describe the purpose and use of the following fuzzing techniques

* Dumb fuzzing techniques
* Code-coverage based fuzzing
* Symbolic execution

[youtube]: https://www.youtube.com/channel/UC6VD4gYf2a6_0hwidZ9PjFA
[clutter-overflow]: picoCTF/binary-exploitation/clutter-overflow
[unsubscriptions]: picoCTF/binary-exploitation/unsubscriptions-are-free
[cache-me-outside]: picoCTF/binary-exploitation/cache-me-outside
[are-you-root]: picoCTF/binary-exploitation/are-you-root
[stonks]: picoCTF/binary-exploitation/stonks
[got_hax]: picoCTF/binary-exploitation/got_hax
[heres-a-libc]: picoCTF/binary-exploitation/heres-a-libc
[level-0]: random-pwnables/level-0/
[level-1]: random-pwnables/level-1/
[guessing-game-1]: picoCTF/binary-exploitation/guessing-game-1/
