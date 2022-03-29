# sum-o-primes

## Introduction

The challenge is a 400 point Cryptography Challenge written by Joshua Inscoe.
The description states:

> We have so much faith in RSA we give you not just the product of the primes,
but their sum as well!

Included files:

* `gen.py`: Generates the primes, generates the flag.
* `output.txt`: Three variable for the RSA calculation.

## Information Gathering

### Hint #1

> I love squares :)

Hmm..., maybe this is referring to value of p and q?

## Background

The RSA algorithm is based on the premise that it is easy to find Y such that Y
= a^X mod p but difficult to find X such that X = log base a of Y mod p. We
aren't going to go into the algorithm itself, but [this][arizona] is a great
resources. We need to find the two prime numbers p and q used

In `output.txt` we are given the following:

* x: the sum of p and q.
* n: the product of p and q.
* c: the ciphertext.

The key here is that we are given the sum of the primes and the product as
well. This makes factoring n=pq easy, because we are constrained to x=p+q.
Given these constraints, we can use `z3` to find our factors p and q.

## Solution

```python
# Define out symbolic input.
p, q = z3.Ints('p q')

# Create a z3 solver and add our constraints. Both x and n exist inside
# `output.txt`.
s = z3.Solver()
s.add(x == p + q, n == p * q)

# Check that we can find a solution to both p and q that satisfy our
constraints.
assert s.check() == z3.sat, 'Could not find a solution.'

# Get our concrete values.
p = s.model()[p].as_long()
q = s.model()[q].as_long()

log.info(f'p is: {p}')
log.info(f'q is: {q}')
```

This yields:

```python
[*] p is:
16174942955622211684807689817589004534369502081188978931064240607298197441822681
67375104518194281247251003508737098570189580597479852595892868941567741477500210
81677541626407361407441784517046578136001286376035902065460778342842546096957253
478986039046139131214800852488780530340489359699975599920445244425139
[*] q is:
12539431177934048779119990116202655705146161490679501122316356071062990821659675
40810597205494970282758253488433204030657442382188042757181526349448953271270372
60388923111346398615163063784803748287612455648597681602167244281188176484278415
540213107535193439007749748790124920127045193879513120171063349588317
```

Knowing p and q, we can now decrypt the ciphertext. Most of the following is
just taken from `gen.py`.

```python
# Calculate the flag.
m = math.lcm(p - 1, q - 1)
d = pow(e, -1, m)
flag = hex(pow(c, d, n))

# Convert from hex to ascii. Skip the first two bytes because they're '0x'.
flag = binascii.unhexlify(flag[2:])
log.success(f'The flag is: {flag}')
```

This yields the flag:

```python
[+] The flag is: b'picoCTF{ee326097}'
```

[arizona]:
https://www.math.arizona.edu/~ura-reports/021/Singleton.Travis/resources/rsabg.htm
