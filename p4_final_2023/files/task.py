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
