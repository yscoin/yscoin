//// rsa_test_04.cpp : 定义控制台应用程序的入口点。
////
//
//
//
//int _tmain(int argc, _TCHAR* argv[])
//{
// return 0;
//}
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
//#include <unistd.h>
#include <iostream>
#include <io.h>
//#pragma comment(lib,"ws2_32.lib")

//maxCodeByte = g_nBits/8-11
const int g_nBits = 1024;
using namespace std;
int MakeKey();

int MakeKey_test_01();
//测试使用PEM_write_bio_RSA_PUBKEY 生成的公钥加密，测试私钥解密
int Enc_test_01(char *in, int inLen, char *out, int &outLen);

int Enc(char *in, int inLen, char *out, int &outLen);

int Dec(char *in, int inLen, char *out, int &outLen);
int DecPub(char *in, int inLen, char *out, int &outLen);
//RSA_PUBKEY

//test base64