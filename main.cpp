#include <iostream>
#include <cstring>
#include "rsa.h"

void clear(){
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

int main(){
    clear();
    std::cout << "Шифрование RSA\n\n" << std::endl;
    
    MyRSA rsa(1024);
    std::cout << "Создан объект RSA" << std::endl;
    
    RSAKeyPair kp = rsa.genpkey();
    rsa.setpkey(kp);
    std::cout << "Ключевая пара сгенерирована!\n" << "e: " << kp.pub << '\n' << "d: " << kp.priv << '\n' << "Модуль n: " << kp.modulus << std::endl;
    
    RSAKey pub = rsa.getPublicKey();
    std::cout << "Открытый ключ (e, n): " << pub.key << ", " << pub.modulus << std::endl;
    
    std::cout << "\nВведите сообщение для шифрования: ";
    char text[1024];
    std::cin.getline(text, sizeof(text));
    
    if(strlen(text) == 0){
        strcpy(text, "Это тестовое сообщение");
    }
    
    BigNum ciphertext = rsa.encrypt(text);
    std::cout << "Исходное сообщение: " << text << std::endl;
    std::cout << "Зашифрованное сообщение (шифртекст): " << ciphertext << std::endl;
    
    const char* decrypted_msg = rsa.decrypt(ciphertext);
    
    if(strcmp(text, decrypted_msg) == 0){
        std::cout << "Сообщение расшифровано корректно! Расшифрованное сообщение: " << decrypted_msg << std::endl;
    } else {
        std::cout << "Ошибка! Расшифрованное сообщение: " << decrypted_msg << std::endl;
        std::cout << "Не совпадает с исходным: " << text << std::endl;
    }
    
    return 0;
}