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
#include <rsa1.h>
const char *g_pPubFile = "pubkey.pem";
const char *g_pPriFile = "prikey.pem";
int MakeKey()
{
	/*if (access(g_pPubFile,0) != 0 || access(g_pPriFile,0) != 0)
	{
	return 0;
	}*/
	//生成key,这里设置了1024，意味着最多可以编解码1024/8-11=117个字节，
	//RSA_F4为公钥指数，一般情况下使用RSA_F4即可，
	//其它两个参数可以设置为NULL
	RSA *pRsa = RSA_generate_key(g_nBits, RSA_F4, NULL, NULL);
	if (pRsa == NULL)
	{
		cout << "rsa_generate_key error" << endl;
		return -1;
	}
	BIO *pBio = BIO_new_file(g_pPubFile, "wb");
	if (pBio == NULL)
	{
		cout << "BIO_new_file " << g_pPubFile << " error" << endl;
		return -2;
	}
	if (PEM_write_bio_RSAPublicKey(pBio, pRsa) == 0)
	{
		cout << "write public key error" << endl;
		return -3;
	}
	BIO_free_all(pBio);

	pBio = BIO_new_file(g_pPriFile, "w");
	if (pBio == NULL)
	{
		cout << "BIO_new_file " << g_pPriFile << " error" << endl;
		return -4;
	}
	if (PEM_write_bio_RSAPrivateKey(pBio, pRsa, NULL, NULL, 0, NULL, NULL) == 0)
	{
		cout << "write private key error" << endl;
		return -5;
	}
	BIO_free_all(pBio);
	RSA_free(pRsa);
	return 0;
}

int MakeKey_test_01()
{
	/*if (access(g_pPubFile,0) != 0 || access(g_pPriFile,0) != 0)
	{
	return 0;
	}*/
	//生成key,这里设置了1024，意味着最多可以编解码1024/8-11=117个字节，
	//RSA_F4为公钥指数，一般情况下使用RSA_F4即可，
	//其它两个参数可以设置为NULL
	RSA *pRsa = RSA_generate_key(g_nBits, RSA_F4, NULL, NULL);
	if (pRsa == NULL)
	{
		cout << "rsa_generate_key error" << endl;
		return -1;
	}
	BIO *pBio = BIO_new_file(g_pPubFile, "wb");
	if (pBio == NULL)
	{
		cout << "BIO_new_file " << g_pPubFile << " error" << endl;
		return -2;
	}
	////PEM_write_bio_RSA_PUBKEY
	//if(PEM_write_bio_RSAPublicKey(pBio,pRsa) == 0)
	if (PEM_write_bio_RSA_PUBKEY(pBio, pRsa) == 0)
	{
		cout << "write public key error" << endl;
		return -3;
	}
	BIO_free_all(pBio);

	pBio = BIO_new_file(g_pPriFile, "w");
	if (pBio == NULL)
	{
		cout << "BIO_new_file " << g_pPriFile << " error" << endl;
		return -4;
	}
	//PEM_write_bio_PKCS8PrivateKey
	if (PEM_write_bio_RSAPrivateKey(pBio, pRsa, NULL, NULL, 0, NULL, NULL) == 0)
		//if(PEM_write_bio_PKCS8PrivateKey(pBio,pRsa,NULL,NULL,0,NULL,NULL) == 0)
	{
		cout << "write private key error" << endl;
		return -5;
	}
	BIO_free_all(pBio);
	RSA_free(pRsa);
	return 0;
}
//测试使用PEM_write_bio_RSA_PUBKEY 生成的公钥加密，测试私钥解密
int Enc_test_01(char *in, int inLen, char *out, int &outLen)
{
	BIO *pBio = BIO_new_file(g_pPubFile, "r");
	//RSA *pRsa = PEM_read_bio_RSAPublicKey(pBio,NULL,NULL,NULL);
	RSA *pRsa = PEM_read_bio_RSA_PUBKEY(pBio, NULL, NULL, NULL);
	BIO_free_all(pBio);
	outLen = RSA_public_encrypt(
		(RSA_size(pRsa) - 11)>inLen ? inLen : RSA_size(pRsa) - 11,
		reinterpret_cast<unsigned char*>(in),
		reinterpret_cast<unsigned char*>(out),
		pRsa,
		RSA_PKCS1_PADDING);
	std::cout << out << std::endl;
	//RSA_free(pRsa);
	if (outLen >= 0)
		return 0;
	return -1;
}

int Enc(char *in, int inLen, char *out, int &outLen)
{
	BIO *pBio = BIO_new_file(g_pPubFile, "r");
	RSA *pRsa = PEM_read_bio_RSAPublicKey(pBio, NULL, NULL, NULL);
	BIO_free_all(pBio);
	int readLength = (RSA_size(pRsa) - 11) > inLen ? inLen : RSA_size(pRsa) - 11;
	outLen = RSA_public_encrypt(
		readLength,
		reinterpret_cast<unsigned char*>(in),
		reinterpret_cast<unsigned char*>(out),
		pRsa,
		RSA_PKCS1_PADDING);
	//std::cout << out << std::endl;
	//RSA_free(pRsa);
	if (outLen >= 0)
		return readLength;
	return -1;
}

int Dec(char *in, int inLen, char *out, int &outLen)
{
	BIO *pBio = BIO_new_file(g_pPriFile, "r");
	RSA *pRsa = PEM_read_bio_RSAPrivateKey(pBio, NULL, NULL, NULL);
	BIO_free_all(pBio);
	outLen = RSA_private_decrypt(
		inLen,
		reinterpret_cast<unsigned char*>(in),
		reinterpret_cast<unsigned char*>(out),
		pRsa,
		RSA_PKCS1_PADDING);
	//RSA_free(pRsa);
	if (outLen >= 0)
		return 0;
	return -1;
}
int DecPub(char *in, int inLen, char *out, int &outLen)
{
	BIO *pBio = BIO_new_file(g_pPubFile, "r");
	RSA *pRsa = PEM_read_bio_RSAPublicKey(pBio, NULL, NULL, NULL);
	BIO_free_all(pBio);
	outLen = RSA_public_decrypt(
		inLen,
		reinterpret_cast<unsigned char*>(in),
		reinterpret_cast<unsigned char*>(out),
		pRsa,
		RSA_PKCS1_PADDING);
	//RSA_free(pRsa);
	if (outLen >= 0)
		return 0;
	return -1;
}
//RSA_PUBKEY

//test base64