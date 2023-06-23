# p4 Final 2023 CTF

## Pallas
> Tell me my secret

And the files: python [script](./files/task.py) with an [output](./files/output.txt):

```python
from pwn import *

from sec import secret
print(len(secret))

text   = b"The Pallas's cat is a highly specialised predator of small mammals, which it catches by stalking or ambushing near exits of burrows."

def bits_to_bytes(l):
	l = [str(f) for f in l]
	l="".join(l)
	final = [l[i * 8:(i + 1) * 8] for i in range((len(l) + 8 - 1) // 8 )]
	final = [int(x,2) for x in final]
	return bytes(final)

def bytes_to_bits(bb):
	r = ""
	for c in bb:
		r += bin(c)[2:].rjust(8,"0")
	r= list(map(int, r))
	return r

def my_crypto_inner(text, secret):
	tl = len(text)
	sl = len(secret)
	enc = [0]*len(text)
	for i in range(tl):
		enc[i]=text[i]
		enc[i]^=secret[i % sl]
		for div in range(1, tl):
			if i%div == 0:
				enc[i] ^= enc[(i-div) % sl]
			if i>0 and div%i == 0:
				enc[i] ^= text[(i-div) % sl]
	return enc

def my_crypto(text, secret):
	text = bytes_to_bits(text)
	secret = bytes_to_bits(secret)
	res = my_crypto_inner(text,secret)
	return bits_to_bytes(res)

encrypted = my_crypto(text,secret)
print(encrypted)
```

Cipher is pretty easy - it has mostly XOR operations, which are simple to inverse. The most importatnt is that line in code:
```python
enc[i]^=secret[i % sl]
```
It is only line refers to `secret` (reminder: this is our flag). So the clue: let's reverse all other operations and check the result with ciphertext. If they are the same - there's `0` in secret. Otherwise - `1`.

Simply code of decrypt function:
```python
def decoder:
    res = []
	tl = len(text)
	sl = 62 * 8                     # secret has 62 bytes = 62 * 8 bits
	i = sl
	while i >= 0:
		div = tl - 1
		while div > 0:
			if i>0 and div%i == 0:
				enc[i] ^= text[(i-div) % sl]
			if i%div == 0:
				enc[i] ^= enc[(i-div) % sl]
			div -= 1
		if(enc[i] == text[i]):
			res.append(0)
		else:
			res.append(1)
		i -= 1
	return (res)
```
And add the rest of program:
```python
text = bytes_to_bits(text)
encrypted = bytes_to_bits(encrypted)
dec = (decoder(encrypted, text))
dec.reverse()
print(bits_to_bytes(dec))
```

And they we have it! **p4{It_4ls0_pu1ls_0ut_rodeNts_with_ITs_pawsFromShallowBurrows.}'**