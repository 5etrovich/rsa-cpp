#ifndef RSA_H
#define RSA_H

#include "bignum.h"

struct RSAKeyPair {
    BigNum pub;
    BigNum priv;
    BigNum modulus;
};

struct RSAKey {
    BigNum key;
    BigNum modulus;
};

std::ostream &operator<<(std::ostream &o, const RSAKeyPair &kp);
std::istream &operator>>(std::istream &i, RSAKeyPair &kp);

std::ostream &operator<<(std::ostream &o, const RSAKey &k);
std::istream &operator>>(std::istream &i, RSAKey &k);

class MyRSA {
private:
    RSAKeyPair KeyPair;
    int key_size;

public:
    MyRSA(int size);
    RSAKeyPair genpkey() const;
    void setpkey(const RSAKeyPair& p);
    RSAKey getPublicKey() const;
    BigNum encrypt(const char* msg) const;
    const char* decrypt(const BigNum& ciphertext) const;
    BigNum process(const BigNum& msg, const RSAKey& key) const;
    BigNum text2bn(const char *) const;
    const char* bn2text(const BigNum&) const;
};

#endif
