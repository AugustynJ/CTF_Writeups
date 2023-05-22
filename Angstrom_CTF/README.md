# ångstromCTF

>Welcome to ångstromCTF, a capture-the-flag (CTF) competition hosted and organized entirely by students at Montgomery Blair High School! CTF cybersecurity competitions have become an increasingly popular way for students to learn more about cybersecurity and develop and refine their hacking skills. These competitions are designed to educate and inspire high school students through interactive hacking challenges.

## Physics HW

> My physics teacher also loves puzzles. Maybe my [homework](./images/physics_hw.png) is a puzzle too?

Definitely our goal is not to solve all the physics questions on sheet of paper - it's miscellaneous challenge!

The flag is hidden inside (But `exiftool` is not adequate).

To deal with this I used [zsetg](https://github.com/zed-0xff/zsteg) - the best stegano tool I've ever used. How to use? simple as that:
```diff
$ zsteg -a physics_hw.png

-b1,rgb,lsb,xy       .. text: "actf{physics_or_forensics}"
b2,r,msb,xy         .. text: "_UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU"
b2,g,msb,xy         .. text: "WUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU"
[...]
```

Under the flag there's milions of sensless signs, but the most importatnt is done: **actf{physics_or_forensics}**

## Impossible
`nc challs.actf.co 32200`

```python
#!/usr/local/bin/python

def fake_psi(a, b):
    return [i for i in a if i in b]

def zero_encoding(x, n):
    ret = []

    for i in range(n):
        if (x & 1) == 0:
            ret.append(x | 1)

        x >>= 1

    return ret

def one_encoding(x, n):
    ret = []

    for i in range(n):
        if x & 1:
            ret.append(x)

        x >>= 1

    return ret

print("Supply positive x and y such that x < y and x > y.")
x = int(input("x: "))
y = int(input("y: "))

if len(fake_psi(one_encoding(x, 64), zero_encoding(y, 64))) == 0 and x > y and x > 0 and y > 0:
    print(open("flag.txt").read())

```

Simple cryptography challenge. Let's solve in steps:

1. `len(fake_psi(...)) == 0) and x > y and x > 0 and y > 0` $\Rightarrow $ function `fake_psi` returns list of objects, so arguments must be zeros.
2. `one_encoding(x, 64)` must equals to $0$. In this case we interpret number in binary form. Something is on the `ret` (like return) list only if the last byte is set as $1$. But how much bytes? It's in $n$ parameter. At the end it removes the last byte. So if we want to get empty output we must submit $x$ number that has $n$ zeros in byte form at the end. In challenge $n=64$, so x that comply with requirements is e. g. $2^{64} = 18446744073709551616$
3. `zero_encoding(y, 64)` must equals to $0$ too. So let's analyze. It's similar to above, but now it appends something to `ret` list if last byte equals to $0$. So we need such $x$, that has $n$ last bytes equal to $1$. In the challenge case $n=64$, so solution can be $2^{64} - 1 = 18446744073709551615$

After submiting such numbers it gives us flag: **actf{se3ms_pretty_p0ssible_t0_m3_7623fb7e33577b8a}**