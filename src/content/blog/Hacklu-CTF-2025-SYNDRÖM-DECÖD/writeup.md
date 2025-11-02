---
author: ch1ko1
title: "Hack.lu CTF 2025 / Crypto / SYNDRÖM DECÖD"
description: "Syndrome Decoding Puzzle - Python Solution"
pubDate: "Nov 02 2025"
heroImage: "/writeups/ch1ko1.jpg"
---

## Challenge
> An IKEA-style flat-pack puzzle: a cryptic instruction sheet, anonymous parts bags, and the tiniest Allen key. Sort, align, and press-fit with care - the chaos resolves into clean Scandinavian order.

The main files provided in the ZIP are:
  - pk.txt : This is a list of bitstrings
  - main.py : This will run as a server and provides us with the syndrome bitstring (though in the format of a vector)

The name is a bit of a big hint as to what we will be doing: Syndroem -> we are looking at parity-checking/syndrome decoding
Related wiki articles for further reading - [Wikipedia - Decoding](https://en.wikipedia.org/wiki/Decoding_methods#Syndrome_decoding) / [proofwiki - Syndrome Decoding](https://proofwiki.org/wiki/Syndrome_Decoding)

### A little bit of recon
The first thing we should do is figure out the implicit parameters
```
[Chikoi@Copland crypto]$ wc -l pk.txt 
2720 pk.txt
[Chikoi@Copland crypto]$ wc -c pk.txt 
2091680 pk.txt
...
2091680 / 2720
=769.0
```
This tells us that there 769 columns, however it is worth noting that this includes the \n column, therefore we actually have **768** columns. When checking the main.py we will see the length of the error vector is 3488. Also from inside the main.py we can see the omega(referred to henceforth as weight or 't') is set to something very low, a mere 4. This is very insecure.

```
3488 - 768 = 2720
n = Error length = 3488
k = Characters per line = 768
r = Number of lines = 2720
t = the target weight = 4
# Notation I am using comes from coding theory
```
Why does it matter? Syndrome decoding is by design exponentially hard and the best method of attack available is a meet-in-the-middle(MITM) attack. This form of attack is quite common in modern cryptography as it gives us a way to reduce the search complexity from a full brute force overall possible vectors all the way down to something much more feasible by splitting the problem into two. If you were to attempt a brute force approach there would be 2^n possible error vectors with the target weight restricted to t=4 we would end up having to brute force C(3488, 4) possible vectors coming out at roughly [6 trillion](https://www.wolframalpha.com/input?i=binomial+calculator&assumption=%22FSelect%22+-%3E+%7B%7B%22BinomialCoefficientCalculator%22%7D%2C+%22dflt%22%7D&assumption=%7B%22F%22%2C+%22BinomialCoefficientCalculator%22%2C+%22n%22%7D+-%3E%223488%22&assumption=%7B%22F%22%2C+%22BinomialCoefficientCalculator%22%2C+%22k%22%7D+-%3E%224%22). This is obviously infeasible and so a MITM approach is preferred.

A man in the middle attack attack would work by first creating two disjointed weight 2 sets, reducing the number of possible vectors to C(3488, 2) or ~6,081,328 partials, we we have to run this twice in order to generate pairs and match them up but working with millions is much more comfortable than trillions.

> C(n, k) is the binomial coefficient, which represents the number of ways to choose k items from n items.

### Code
Annoyingly, the server provides the syndrome in the form of a tuple so I created this miniscript in 1 tab to quickly copy and paste what I got and turn it into something more usable...
```python
>>> a = ''
>>> a = '(0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1,\
 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0,\
 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1,\
 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,\
 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0,\
 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0,\
 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1,\
 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1,\
 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0,\
 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0,\
 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0,\
 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0,\
 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1)'
>>> import re; b = re.sub(r'[^01]', '', a)
>>> b
'000011001011110101111111011001110010000110110000001000010001100001001001110110110111000111000101000111001010111011001011010110101000111000111100001011110000101001110101100001110111101001000000111001101011001111110100101111101001101011011000000000000100000100001101000100101110100011110011100011011010010101111000111111110101010001111000100001100000111110010101101100010011000011010001111011001010010110001101110000111111010110000100001001111010000110110111001000000010011110000110100001110110011111111101101100000000111010010000101001111010110110000011010110110010110001010001100010101000111100011110000100010010011100100000110111111101111000000011011100111100111000001001100101001100011010001011001011100001000111100000101000101101000101100010101011010110110110011111'
```

Solver code - It's a bit rough and could probably be faster, but it solves the challenge in about 5 seconds. Pre-emptive optimisation? That's your sin, not mine.

```python
#!/usr/bin/env python3
import sys, time
from collections import defaultdict

def read_pk(path="pk.txt"):
    with open(path, "r") as f:
        lines = [ln.strip() for ln in f if ln.strip()]
    # parameters implied by the challenge:
    r = 768
    k = 2720
    n = 3488
    if len(lines) != k:
        raise RuntimeError(f"expected {k} lines in pk.txt but found {len(lines)}")
    cols = [0]*n
    # unit vectors for positions 0..r-1
    for i in range(r):
        cols[i] = 1 << i
    # remaining positions: each line is a 768-bit column, with bit 0 at leftmost char
    for idx, line in enumerate(lines):
        if len(line) != r:
            raise RuntimeError(f"line {idx+1} length {len(line)} != {r}")
        v = 0
        # line[0] corresponds to bit 0
        # to be consistent with encode.sage: row i is the i-th bit
        for i,ch in enumerate(line):
            if ch == '1':
                v |= (1 << i)
        cols[r + idx] = v
    return cols

def find_weight4_by_pairs(cols, target):
    n = len(cols)
    pairmap = dict()   # xor_value -> (i,j) (store one pair per xor)
    start = time.time()
    print("Building pair map...")
    # store pair xor -> one pair (i,j)
    for i in range(n):
        ci = cols[i]
        # iterate j>i
        for j in range(i+1, n):
            x = ci ^ cols[j]
            if x not in pairmap:
                pairmap[x] = (i,j)
        if i % 200 == 0:
            elapsed = time.time() - start
            print(f"  processed i={i}/{n} pairs stored={len(pairmap):,} elapsed={elapsed:.1f}s")
    print("Searching for matching two pairs...")
    # Search: find x such that (target ^ x) in pairmap and pairs disjoint
    for x, (i,j) in pairmap.items():
        need = target ^ x
        if need in pairmap:
            a,b = pairmap[need]
            if len({i,j,a,b}) == 4:
                # found
                return sorted([i,j,a,b])
    return None

def main():
    if len(sys.argv) < 2:
        print("Usage: python new_new_new_solver.py <syndrome_binary_string>")
        sys.exit(1)
    syndrome_str = sys.argv[1].strip()
    if len(syndrome_str) != 768:
        print("Warning: syndrome length is not 768 bits (got {}). Proceeding anyway.".format(len(syndrome_str)))
    # parse syndrome string -> integer with bit 0 from leftmost char
    target = 0
    for i,ch in enumerate(syndrome_str):
        if ch == '1':
            target |= (1 << i)
    print("Reading in pk.txt...")
    cols = read_pk("pk.txt")
    print("pk loaded, n =", len(cols))
    t0 = time.time()
    sol = find_weight4_by_pairs(cols, target)
    t1 = time.time()
    if sol:
        print("Found solution indices (0-based):", sol)
        n = len(cols)
        e_bits = ['0']*n
        for p in sol:
            e_bits[p] = '1'
        e_str = ''.join(e_bits)
        print("Error vector ({} bits):".format(len(e_str)))
        print(e_str)
        print("Done in {:.1f}s".format(t1-t0))
    else:
        print("No solution found (weight-4). Time: {:.1f}s".format(t1-t0))

if __name__ == "__main__":
    main()
```
TL;DR - Here is what it does step by step:
  1. Reads pk.txt, double checks the line and length counts before building an array `cols` of n=3488 integers
  2. Converts the user input snydrome string into an integer `target` with the same bit ordering as `cols`
  3. Iterates all unordered index pairs `(i,j)`, computes the XOR `x = cols[i] ^ cols[j]`, and inserts `pairmap[x] = (i,j)` - For the sake of debugging it prints out every 200 XORs
  4. For each pair xor `x` in `pairmap`, compute `need = target ^ x`
  5. Check that the four indices are distinct `{i, j, a, b}` and if so, reconstruct the 4-bit error vector
  6. print the first found valid full 3488-bit error vector, plus the elapsed time.

### Solved
Copy the syndrome -> Clean the syndrome input -> run the solver.py -> return the error
```
[Chikoi@Copland crypto]$ nc -v localhost 5555
Connection to localhost (::1) 5555 port [tcp/personal-agent] succeeded!
Welcome to Roberts Construction Service!
Your syndrome:
(0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1)
Enter the error:
00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000

FLAG_CENSORED

```

### Extra

If you would like to try find your own solution flux has an archive currently up, it will likely stay up for awhile, however it won't print out the flag when you download and set it up locally.

https://archive.fluxfingers.net/2025/challenges/17.html - if this goes down I will replace it with a github link to a zip file for this challenge

Provided below is how to set it up and run it with docker
```
cd ~/fluxxx-2025/{unzipped folder}/
sudo docker build -t syndroem .
sudo docker run --rm -p 5555:5555 --name syndroem syndroem
```

You can use the method I use above to connect relying on netcat or you can use pwntools to connect to localhost:5555
