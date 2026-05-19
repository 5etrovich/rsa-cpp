# rsa-cpp

RSA encryption algorithm implemented from scratch in C++98, without high-level crypto functions.

## What's implemented

- BigNum class — arbitrary precision arithmetic via OpenSSL BIGNUM:
  - mod_exp — fast modular exponentiation
  - mod_inv — modular inverse (extended Euclidean algorithm)
  - coprime — coprimality check
  - prime(bits) — prime number generation

- MyRSA class:
  - genpkey() — generate key pair (public + private + modulus)
  - encrypt(msg) — text to BigNum, then modular exponentiation
  - decrypt(ciphertext) — reverse operation
  - `text2bn` / `bn2text` — text <-> BigNum conversion

## Build

`ash
make
`

Requires: GCC, OpenSSL (-lcrypto)

## Stack

C++98, OpenSSL BIGNUM, GNU Make, Linux
