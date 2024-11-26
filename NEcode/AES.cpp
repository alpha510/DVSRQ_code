//
// Created by baija on 2023/9/12.
//

#include "AES.h"


int AES::encStr(std::string plainText, int plainTextLen, unsigned char *cipherText) {
    return 0;
}

int AES::encCharArr(unsigned char *plainText, int plainTextLen, unsigned char *cipherText) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int cipherTextLen;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();


    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, m_key, m_iv))
        handleErrors();




    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, cipherText, &len, plainText, plainTextLen))
        handleErrors();
    cipherTextLen = len;

    /*
     *
     *
     */
    EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

    /*
     * Finalise the encryption. Further cipherText bytes may be written at
     * this stage.
     */
    if (1 != EVP_EncryptFinal_ex(ctx, cipherText + len, &len))
        handleErrors();
    cipherTextLen += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return cipherTextLen;
}

int AES::encPaddingStr(std::string plainText, unsigned char *cipherText, int &cipherTextLen) {
    if (plainText.length() + 1 > cipherTextLen - 16) {
        printf("密文长度太短\n");
        return 1;
    }
    if (cipherTextLen % 16 != 0) {
        printf("密文长度不为的16的整数倍\n");
        return 1;
    }
    char *charArrPlainText = new char[cipherTextLen - 16];
    memset(charArrPlainText, 0, cipherTextLen - 16);
    memset(cipherText, 0, cipherTextLen);
    strncpy(charArrPlainText, plainText.c_str(), plainText.length());
    charArrPlainText[plainText.length()] = '\0';

    //测试，strncpy是否只拷贝n个元素，不包含\0
//    printf("%s\n",charArrPlainText);

    int tmpCipherTextLen = encCharArr((unsigned char*)charArrPlainText, cipherTextLen - 16, cipherText); // 让它自动padding填充16个字节，保证最终加密大小和设置的相同
    delete []charArrPlainText;
    if (tmpCipherTextLen != cipherTextLen){
        printf("输出的密文长度与输入的密文长度不一致\n");
        return 1;
    }
    return 0;
}

int AES::encPaddingCharArr(unsigned char *plainText, int plainTextLen, unsigned char *cipherText, int &cipherTextLen) {

    if (cipherTextLen < plainTextLen + 16) {
        printf("输入的密文长度不足以容纳密文\n");
        return 1;
    }
     if(cipherTextLen % 16 != 0) {
         printf("密文长度不为的16的整数倍\n");
         return 1;
     }

    char *charArrPlainText = new char[cipherTextLen - 16];
    memset(charArrPlainText, 0, cipherTextLen - 16);
    memset(cipherText, 0, cipherTextLen);
    strncpy(charArrPlainText, (char*)plainText, plainTextLen);
    charArrPlainText[cipherTextLen] = '\0';

    cipherTextLen = encCharArr((unsigned char*)charArrPlainText, cipherTextLen-16, cipherText); // 让它自动padding填充16个字节，保证最终加密大小和设置的相同
    delete[] charArrPlainText;
    if (cipherTextLen != plainTextLen + 16) {
        printf("输出的密文长度不为明文长度+16\n");
        return 1;
    }

    return 0;
}

int AES::decStr(std::string cipherText, int cipherTextLen, unsigned char *plainText) {

    return 0;
}

int AES::decCharArr(unsigned char *cipherText, int cipherTextLen, unsigned char *plainText) {
    EVP_CIPHER_CTX* ctx;

    int len;

    int plainTextLen;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, this->m_key, this->m_iv))
        handleErrors();

    /*
     *
     *
     */
    EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

    /*
     * Provide the message to be decrypted, and obtain the plainText output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if (1 != EVP_DecryptUpdate(ctx, plainText, &len, cipherText, cipherTextLen))
        handleErrors();
    plainTextLen = len;

    /*
     * Finalise the decryption. Further plainText bytes may be written at
     * this stage.
     */
    if (1 != EVP_DecryptFinal_ex(ctx, plainText + len, &len))
        handleErrors();
    plainTextLen += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plainTextLen;
    return 0;
}

int AES::decPaddingCharArr2Str(unsigned char *cipherText, int cipherTextLen, std::string &plainStr) {
    if (cipherTextLen % 16 != 0) {
        printf("输入的密文长度不为16的整数倍\n");
        return 1;//传入长度不为16的整数倍则返回错误
    }
    unsigned char *plainText = new unsigned char [cipherTextLen];
    memset(plainText,0,cipherTextLen);
    int tmpPlainTextLen = decCharArr(cipherText, cipherTextLen, plainText);
    plainStr = (char*)plainText;
    delete[] plainText;
    return 0;
}

int AES::decPaddingCharArr(unsigned char *cipherText, int cipherTextLen, unsigned char *plainText, int &plainTextLen) {
    if (cipherTextLen % 16 != 0) {
        printf("输入的密文长度不为16的整数倍\n");
        return 1;//传入长度不为16的整数倍则返回错误
    }
    if(plainTextLen +16 > cipherTextLen){
        printf("输入的明文长度不为密文长度-16\n");
        return 1;//传入长度不为16的整数倍则返回错误
    }
    memset(plainText,0,plainTextLen);
    int tmpPlainTextLen = decCharArr(cipherText, cipherTextLen, plainText);
    if(tmpPlainTextLen > cipherTextLen){
        printf("解密后的明文长度不正确\n");
        return 1;//传入长度不为16的整数倍则返回错误
    }
    if(tmpPlainTextLen != plainTextLen){
        printf("解密后的明文长度与输入的明文长度不匹配\n");
    }
    plainTextLen = tmpPlainTextLen;
    return 0;
}

int AES::setKey(unsigned char *key) {
    delete []this->m_key;
    this->m_key = key;
    return 0;
}

int AES::setIv(unsigned char *iv) {
    delete []this->m_iv;
    this->m_iv = iv;
    return 0;
}

int AES::handleErrors() {
    printf("有错误");
    return 0;
}

AES::AES(std::string key, std::string iv){

    this->m_key = new unsigned char[key.length()+1];
    this->m_iv =  new unsigned char[iv.length()+1];
    memset(this->m_key, 0, key.length()+1);
    memset(this->m_iv, 0, iv.length()+1);

    strncpy((char*)(this->m_key), key.c_str(), key.length() + 1);
    strncpy((char*)(this->m_iv), iv.c_str(), iv.length() + 1);

}
AES::AES(std::string key){

    std::string iv = "0123456789012345";
    this->m_key = new unsigned char[key.length()+1];
    this->m_iv =  new unsigned char[iv.length()+1];
    memset(this->m_key, 0, key.length()+1);
    memset(this->m_iv, 0, iv.length()+1);

    strncpy((char*)(this->m_key), key.c_str(), key.length() + 1);
    strncpy((char*)(this->m_iv), iv.c_str(), iv.length() + 1);

}

AES::~AES() {
    delete[] m_key;
    delete[] m_iv;
}
