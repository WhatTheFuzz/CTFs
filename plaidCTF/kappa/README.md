# kappa

## Introduction

`kappa` is an old 2014 CTF challenge from plaidCTF. It looked like a lot of fun,
so I figured I'd give it a whirl.

### Included Files:

* `kappa` - the x86 executable.
* `kappa_patched` - the x86 executable, modified to never sleep.
* `hook.so` - a shared library that patches the sleep function in `kappa`
  to never sleep. This isn't necessary if using the `kappa_patched` binary.
* `solve.py` - a python script that solves the challenge.
* `src/` - a directory containing the source code for the challenge.

## Information Gathering

No hints were given, but we do have source code.

### Vulnerability Mitigations

```shell
$ checksec ./kappa
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000
```

Note that `kappa_patched` will be different; I didn't use the additional flags.

### Static

It's a Pokemon challenge! It looks like we will walk around and catch some
Pokemon and add them to our party. Three different Pokemon are defined as
structure, each of varying sizes.

```c
typedef struct Charizard {
    char name[15];
    char art[sizeof(charizard_art)+1];
    int health;
    int attack;
    char ** attack_name;
    void (*print_pokemon) (struct Charizard *);
} Charizard;
void print_charizard(Charizard *c);
typedef struct Kakuna {
    char name[15];
    char art[sizeof(kakuna_art)+1];
    int health;
    int attack;
    char ** attack_name;
    void (*print_pokemon) (struct Kakuna *);
} Kakuna;
typedef struct Pidgeot {
    char name[15];
    char art[sizeof(pidgeot_art)+1];
    int health;
    int attack;
    char ** attack_name;
    void (*print_pokemon) (struct Pidgeot *);
} Pidgeot;
```

The program grabs input from the user via `getchar()`. We can do things like
walk in the grass, inspect our Pokemon, heal them, release them, and change
their artwork (which uses `read` to nab up 4000 byte from the user).

While looking at `change_art`, I noticed that it will only allow up to
`strlen(pidgeot->art)` bytes to be read, regardless of which Pokemon we are
changing. So if we caught a Kakuna and changed its artwork, the program would
still cast the Pokemon as a Pidgeot struct. Considering they are at the same
offset, I don't think this is a problem necessarily, but it is compiler
implementation specific how structures are laid out in memory. This is a bug,
even if we can't exploit it.

Here's the real bug though. When we catch a Pokemon, we update our party with
this little subroutine in `fight`:

```c
pokemon_list[i] = enemy;
pokemon_type[i] = type;
return;
```

This updates our party to reflect both the Pokemon we have the what 'type' it
is (the 'type' actually refers to the `pokemon_t` enum, which can be a Ratata,
Kakuna, Pidgeot, or a Charizard; not like flying and bug if you're familiar
with actual Pokemon).

But what happens when we reach five Pokemon in our party and catch one more
(the maximum size; not six like in the actual games)? In `fight`, we are
prompted to release a Pokemon to make room for the one we just caught. The
logic there is slightly different:

```c
printf("Oh no! you don't have any more room for a Pokemon! Choose a pokemon to replace!\n");
size_t choice = list_pokemon_choices();
if (choice == 0) {
    printf("%s can't be freed!\n", (char *)pokemon_list[0]);
    return;
}
if (choice > 4) {
    printf("Invalid Choice!\n");
    return;
}
free(pokemon_list[choice]);
pokemon_list[choice] = enemy;
return
```

Notice that last bit. The developer forgot to update the Pokemon's typing. So
if we caught a Charizard and just replaced a Kakuna, the program would still
believe that the Pokemon we just caught is a Kakuna. The problem with this is
that the structure for Kakuna and Charizard are completely different sizes.
Charizard has an `art` object size of 2151 bytes. Kakuna has one of 501 bytes.

This becomes a problem when we select the option `3. Inpect your Pokemon`. This
functions will go through each Pokemon in our party and print out the name,
health, attack, and artwork. Normally this is fine, but if the program believes
our Charizard is really a Kakuna, problems arise. To print out the artwork,
there is a function in each of the Pokemons' structs that prints out the
artwork. This lies at the very end of the structure (again, implementation
specific). Given the differences in the size of the `art` objects, the offsets
to these functions will vary between the Pokemon. For Kakuna it will be
somewhere around Kakuna + 540 bytes. For Charizard it is somewhere around
Charizard + 2175 bytes.

Okay, okay, so what? Well, when the program tries to call Kakuna->print_pokemon
(at offset ~ +540 bytes) on what is actually a Charizard, it will actually try
and treat some offset into the `art` object as a function pointer. This will
cause the program to segfault, as our ascii characters probably aren't valid
pointers. This is a case of structure type confusion.

## Strategy

Based on what we observed above, we wrote a script to catch four Kakunas and
then keep going into the grass until we battle a Charizard. When we catch the
Charizard we have to release one of the Kakunas. We arbitrarily chose the third
one. We then change the artwork of the Charizard to a cyclic pattern to
determine the offset to the `print_pokemon` function pointer.

Doing this gave us an offset of 513. This is where we're currently stuck
though. We have a non-executable stack so we're probably going to have to ROP.
However, we were not given a `libc` to look at. The current thought is to jump
the PLT to call `puts` and pass in the GOT entry for some `libc` functions.
From this, we might be able to figure out what version of `libc` we're using
and calculate the address of `system`.

## Solution (TODO)

Other [writeups][skull] we found for this problem rely on solving previous
challenges from plaidCTF 2014, getting a shell via those challenges, and then
looking at what `libc` they're using. We don't have that luxury, so we might
come back to this problem later with a known version of `libc`.

Unless anyone else has any ideas? For now, the `solve.py` script will just get
you $EIP control.

[skull]:
https://blog.skullsecurity.org/2014/plaidctf-writeup-for-pwn-275-kappa-type-confusion-vuln
