//
// Created by baija on 2023/9/12.
//

#ifndef DISECDB_AES_H
#define DISECDB_AES_H

#include "stdio.h"
#include <openssl/evp.h>
#include <string>
#include <string.h>

class AES {
private:
    unsigned char* m_key;     //加密密钥
    unsigned char* m_iv;      //初始化向量
public:
    /**
     * @name AES
     * @brief 初始化AES类，需要传入密钥和初始化向量
     * @param key std::string 密钥
     * @param iv std::string 初始化向量
     */
    AES(std::string key,std::string iv);
    AES(std::string key);

    /**
     * @name encStr
     * @brief 加密string类型明文，目前未实现
     * @param plainText std::string 输入明文
     * @param plainTextLen int 明文长度
     * @param cipherText unsigned char* 输出密文
     * @return int 密文长度
     */
    int encStr(std::string plainText, int plainTextLen, unsigned char* cipherText);

    /**
     * @name encCharArr
     * @brief 加密char数组类型明文
     * @param plainText unsigned char* 输入明文
     * @param plainTextLen int 明文长度
     * @param cipherText unsigned char* 输出密文，需要在传入前分配好内存空间，至少比明文长度多16个字节
     * @return
     */
    int encCharArr(unsigned char* plainText, int plainTextLen, unsigned char* cipherText);



    /**
     * @name encPaddingStr
     * @brief 对string类型明文加密进行padding，输出指定长度的char*类型的密文
     * @param plainText std::string 输入明文，字符串应当为\0结尾
     * @param ciphertext unsigned char* 输出密文，长度为指定密文长度
     * @param cipherTextLen int & 输入密文长度，在加密校验长度后原样输出，长度需要至少是明文长度+1+16，并且是16的整数倍
     * @return int 成功与否
     */


    int encPaddingStr(std::string plainText, unsigned char* ciphertext, int &cipherTextLen);


    /**
     * @name encPaddingCharArr
     * @brief 对char*数组类型的明文进行padding加密
     * @param plainText unsigned char* 输入明文
     * @param plainTextLen int 输入明文长度
     * @param ciphertext unsigned char* 输出密文
     * @param cipherTextLen int 输出密文长度
     * @return int 成功与否
     */

    int encPaddingCharArr(unsigned char* plainText, int plainTextLen, unsigned char* ciphertext, int &cipherTextLen);

    /**
     * @name decStr
     * @brief 对string类型解密，未实现
     * @param cipherText std::string 输入密文
     * @param cipherTextLen int 密文长度，必须是16的整数倍
     * @param plainText unsigned char* 输出明文
     * @return int  明文长度
     */

    int decStr(std::string cipherText, int cipherTextLen, unsigned char* plainText);


    /**
     * @name decCharArr
     * @brief 对char数组类型解密
     * @param cipherText 输入密文
     * @param cipherTextLen 密文长度，必须是16的整数倍
     * @param plainText 输出明文
     * @return int 密文长度
     */
    int decCharArr(unsigned char* cipherText, int cipherTextLen, unsigned char* plainText);



    /**
     * @name decPaddingCharArr2Str
     * @brief 将unsigned char * 类型的密文解密为std::string类型的明文，其中明文必须是以\0结尾的字符串
     * @param cipherText 输入密文
     * @param cipherTextLen 密文长度
     * @param plainStr 输出明文，明文必须以\0结尾
     * @return int 成功与否
     */
    int decPaddingCharArr2Str(unsigned char *cipherText, int cipherTextLen, std::string &plainStr);


    /**
     * @name decPaddingCharArr
     * @brief 将padding过的char*类型密文进行解密
     * @param cipherText  unsigned char* 输入密文
     * @param cipherTextLen int 密文长度，必须是16的整数倍
     * @param plainText  unsigned char* 输出明文
     * @param plainTextLen int 明文长度，明文长度为密文长度-16
     * @return
     */
    int decPaddingCharArr(unsigned char* cipherText, int cipherTextLen, unsigned char* plainText, int &plainTextLen);


    /**
     * @name setKey
     * @brief 设置密钥，不使用该函数
     * @param key unsigned char* 密钥
     * @return int 成功与否
     */
    int setKey(unsigned char* key);


    /**
     * @name setIv
     * @brief 设置初始向量iv，不使用该函数
     * @param iv  unsigned char* 初始向量
     * @return int 成功与否
     */
    int setIv(unsigned char* iv);

    /**
     * @name ~AES
     * @brief 析构函数，将存储密钥key和初始化向量iv的空间释放
     */
    ~AES();
private:
    /**
     * @name handleErrors
     * @brief 有错误时打印错误
     * @return int 成功与否
     */
    int handleErrors();
};


#endif //DISECDB_AES_H
