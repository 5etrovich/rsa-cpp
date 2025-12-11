#include "rsa.h"
#include <cstring>
#include <cstdlib>
#include <sstream>
#include <cstdio>
#include <vector>

std::ostream &operator<<(std::ostream& o, const RSAKeyPair& kp){
    o << kp.pub << std::endl;
    o << kp.priv << std::endl;
    o << kp.modulus << std::endl;
    return o;
}

std::istream &operator>>(std::istream& i, RSAKeyPair& kp){
    i >> kp.pub >> kp.priv >> kp.modulus;
    return i;
}

std::ostream &operator<<(std::ostream& o, const RSAKey& k){
    o << k.key << std::endl;
    o << k.modulus << std::endl;
    return o;
}

std::istream &operator>>(std::istream& i, RSAKey& k){
    i >> k.key >> k.modulus;
    return i;
}

MyRSA::MyRSA(int size) : key_size(size){
    KeyPair.pub = BigNum("0");
    KeyPair.priv = BigNum("0");
    KeyPair.modulus = BigNum("0");
}

RSAKeyPair MyRSA::genpkey() const{
    RSAKeyPair kp;
    BigNum p = BigNum::prime(key_size);
    BigNum q = BigNum::prime(key_size);
    kp.modulus = p * q;
    
    BigNum phi = (p - BigNum("1")) * (q - BigNum("1"));
    kp.pub = BigNum("65537");
    
    int att = 0;
    while(!kp.pub.coprime(phi) && att < 100){
        kp.pub = BigNum::prime(17);
        ++att;
    }
    
    kp.priv = kp.pub.mod_inv(phi);
    return kp;
}

void MyRSA::setpkey(const RSAKeyPair& kp){
    KeyPair = kp;
}

RSAKey MyRSA::getPublicKey() const{
    RSAKey pub;
    pub.key = KeyPair.pub;
    pub.modulus = KeyPair.modulus;
    return pub;
}

BigNum MyRSA::process(const BigNum& message, const RSAKey& key) const {
    if(key.modulus == BigNum("0")){
        std::cerr << "Ключ не установлен!" << std::endl;
        return BigNum("0");
    }
    
    if(message >= key.modulus){
        std::cerr << "Сообщение больше или равно модулю!" << std::endl;
        return BigNum("0");
    }
    
    return message.mod_exp(key.modulus, key.key);
}

BigNum MyRSA::text2bn(const char* text) const {
    if(!text || strlen(text) == 0){
        return BigNum("0");
    }
    
    std::vector<int> bytes;
    for(size_t i = 0; i < strlen(text); ++i){
        bytes.push_back((int)(unsigned char)text[i]);
    }
    
    BigNum result("0");
    BigNum base("256");
    
    for(size_t i = 0; i < bytes.size(); ++i){
        result = result * base;
        
        char buf[16];
        sprintf(buf, "%d", bytes[i]);
        result = result + BigNum(buf);
    }
    
    return result;
}

const char* MyRSA::bn2text(const BigNum& bn) const{
    static char buf[4096];
    memset(buf, 0, sizeof(buf));
    
    BigNum num = bn;
    BigNum zero("0");
    BigNum base("256");
    
    if(num == zero){
        buf[0] = '\0';
        return buf;
    }
    
    std::vector<int> bytes;
    while(num > zero){
        BigNum rem = num - ((num / base) * base);
        
        std::ostringstream os;
        os << rem;
        
        int byte_value = 0;
        std::string rem_str = os.str();
        
        for(size_t j = 0; j < rem_str.size(); ++j){
            char c = rem_str[j];
            byte_value = byte_value * 10 + (c - '0');
        }
        
        bytes.push_back(byte_value);
        num = num / base;
    }
    
    size_t pos = 0;
    for(int i = (int)bytes.size() - 1; i >= 0; --i){
        if(pos < sizeof(buf) - 1){
            buf[pos++] = (char)bytes[i];
        }
    }
    
    buf[pos] = '\0';
    return buf;
}

BigNum MyRSA::encrypt(const char* msg) const {
    BigNum message = text2bn(msg);
    RSAKey pub_key = getPublicKey();
    std::cout << "Сообщение в виде числа: " << message << std::endl;
    return process(message, pub_key);
}

const char* MyRSA::decrypt(const BigNum& ciphertext) const{
    RSAKey priv_key;
    priv_key.key = KeyPair.priv;
    priv_key.modulus = KeyPair.modulus;
    BigNum message = process(ciphertext, priv_key);
    std::cout << "Расшифрованное число: " << message << std::endl;
    return bn2text(message);
}