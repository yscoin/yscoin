//demo.cpp
// g++ demo.cpp -o demo -lcrypto
#include "RSA.h"
using namespace std;
//const string PublicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHzOUy99dm5YfxvZyYMmxWiOwUdEpr / lBr3Bx9qIJ3OKI5iVXFyEyEojkwgb5201yslNHHHxYmOukF7X7569kj / bIRs32TdUFbEQeC8KxuM8n85dOXQgc185yOZK6XTaLTEbtEHNllig4uksFXtDf0bq6d6CtsBgY0W + cgZzgsmQIDAQAB";
//加密
std::string EncodeRSAKeyFilePub(const std::string& strPemFileName, const std::string& strData)
{
	if (strPemFileName.empty() || strData.empty())
	{
		assert(false);
		return "";
	}
	FILE* hPubKeyFile = fopen(strPemFileName.c_str(), "rb");
	if (hPubKeyFile == NULL)
	{
		assert(false);
		return "";
	}
	std::string strRet;
	RSA* pRSAPublicKey = RSA_new();
	if (PEM_read_RSA_PUBKEY(hPubKeyFile, &pRSAPublicKey, 0, 0) == NULL)
	{
		assert(false);
		return "";
	}

	int nLen = RSA_size(pRSAPublicKey);
	char* pEncode = new char[nLen + 1];
	int ret = RSA_public_encrypt(strData.length(), (const unsigned char*)strData.c_str(), (unsigned char*)pEncode, pRSAPublicKey, RSA_PKCS1_PADDING);
	if (ret >= 0)
	{
		strRet = std::string(pEncode, ret);
	}
	delete[] pEncode;
	RSA_free(pRSAPublicKey);
	fclose(hPubKeyFile);
	CRYPTO_cleanup_all_ex_data();
	return strRet;
}
std::string EncodeRSAKeyFilePri(const std::string& strPemFileName, const std::string& strData)
{
	if (strPemFileName.empty() || strData.empty())
	{
		assert(false);
		return "";
	}
	FILE* hPubKeyFile = fopen(strPemFileName.c_str(), "rb");
	if (hPubKeyFile == NULL)
	{
		assert(false);
		return "";
	}
	std::string strRet;
	RSA* pRSAPublicKey = RSA_new();
	if (PEM_read_RSAPrivateKey(hPubKeyFile, &pRSAPublicKey, 0, 0) == NULL)
	{
		assert(false);
		return "";
	}

	int nLen = RSA_size(pRSAPublicKey);
	char* pEncode = new char[nLen + 1];
	int ret = RSA_private_encrypt(strData.length(), (const unsigned char*)strData.c_str(), (unsigned char*)pEncode, pRSAPublicKey, RSA_PKCS1_PADDING);
	if (ret >= 0)
	{
		strRet = std::string(pEncode, ret);
	}
	delete[] pEncode;
	RSA_free(pRSAPublicKey);
	fclose(hPubKeyFile);
	CRYPTO_cleanup_all_ex_data();
	return strRet;
}
std::string EncodeRSAKeyPub(const std::string& strData)
{
	string strPublicKey(PublicKey);
	int nPublicKeyLen = strPublicKey.size();      //strPublicKey为base64编码的公钥字符串
	for (int i = 64; i < nPublicKeyLen; i += 64)
	{
		if (strPublicKey[i] != '\n')
		{
			strPublicKey.insert(i, "\n");
		}
		i++;
	}
	strPublicKey.insert(0, "-----BEGIN PUBLIC KEY-----\n");
	strPublicKey.append("\n-----END PUBLIC KEY-----\n");
	std::string strRet;
	BIO *bio = NULL;
	RSA *pRSAPublicKey = NULL;
	char *chPublicKey = const_cast<char *>(strPublicKey.c_str()); // const_cast<char *>(strPublicKey);
	//BIO_read(bio, chPublicKey, strlen(pubKey));
	if ((bio = BIO_new_mem_buf(chPublicKey, -1)) == NULL)       //从字符串读取RSA公钥
	{
		cout << "BIO_new_mem_buf failed!" << endl;
	}
	pRSAPublicKey = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);   //从bio结构中得到rsa结构

	int nLen = RSA_size(pRSAPublicKey);
	char* pEncode = new char[nLen + 1];
	int ret = RSA_public_encrypt(strData.length(), (const unsigned char*)strData.c_str(), (unsigned char*)pEncode, pRSAPublicKey, RSA_PKCS1_PADDING);
	if (ret >= 0)
	{
		strRet = std::string(pEncode, ret);
	}
	delete[] pEncode;
	RSA_free(pRSAPublicKey);
	CRYPTO_cleanup_all_ex_data();
	return strRet;
}
int EncodeRSAKeyPubToFile(const std::string& strData,const std::string& saveFilename)
{
	std::string strRet;
	FILE *f = fopen(saveFilename.c_str(), "wb");
	int readLength = 0;
	if (f)
	{
		string strPublicKey(PublicKey);
		int nPublicKeyLen = strPublicKey.size();      //strPublicKey为base64编码的公钥字符串
		for (int i = 64; i < nPublicKeyLen; i += 64)
		{
			if (strPublicKey[i] != '\n')
			{
				strPublicKey.insert(i, "\n");
			}
			i++;
		}
		strPublicKey.insert(0, "-----BEGIN PUBLIC KEY-----\n");
		strPublicKey.append("\n-----END PUBLIC KEY-----\n");
		
		BIO *bio = NULL;
		RSA *pRSAPublicKey = NULL;
		char *chPublicKey = const_cast<char *>(strPublicKey.c_str()); // const_cast<char *>(strPublicKey);
		//BIO_read(bio, chPublicKey, strlen(pubKey));
		if ((bio = BIO_new_mem_buf(chPublicKey, -1)) == NULL)       //从字符串读取RSA公钥
		{
			cout << "BIO_new_mem_buf failed!" << endl;
		}
		pRSAPublicKey = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);   //从bio结构中得到rsa结构
		readLength = (RSA_size(pRSAPublicKey) - 11) > strData.length() ? strData.length() : RSA_size(pRSAPublicKey) - 11;
		int nLen = RSA_size(pRSAPublicKey);
		char* pEncode = new char[nLen + 1];
		int ret = RSA_public_encrypt(readLength, (const unsigned char*)strData.c_str(), (unsigned char*)pEncode, pRSAPublicKey, RSA_PKCS1_PADDING);
		if (ret >= 0)
		{
			strRet = std::string(pEncode, ret);
		}
		delete[] pEncode;
		RSA_free(pRSAPublicKey);
		CRYPTO_cleanup_all_ex_data();
		//std::vector<char> v(strRet.begin(), strRet.end());

		size_t length = strRet.size();
		fwrite(&length, sizeof(unsigned long), 1, f);
		fwrite(&strRet[0], strRet.size(), 1, f);
		fclose(f);
	}
	return readLength;
}
//解密
std::string DecodeRSAKeyFilePri(const std::string& strPemFileName, const std::string& strData)
{
	if (strPemFileName.empty() || strData.empty())
	{
		assert(false);
		return "";
	}
	FILE* hPriKeyFile = fopen(strPemFileName.c_str(), "rb");
	if (hPriKeyFile == NULL)
	{
		assert(false);
		return "";
	}
	std::string strRet;
	RSA* pRSAPriKey = RSA_new();
	if (PEM_read_RSAPrivateKey(hPriKeyFile, &pRSAPriKey, 0, 0) == NULL)
	{
		assert(false);
		return "";
	}
	int nLen = RSA_size(pRSAPriKey);
	char* pDecode = new char[nLen + 1];

	int ret = RSA_private_decrypt(strData.length(), (const unsigned char*)strData.c_str(), (unsigned char*)pDecode, pRSAPriKey, RSA_PKCS1_PADDING);
	if (ret >= 0)
	{
		strRet = std::string((char*)pDecode, ret);
	}
	delete[] pDecode;
	RSA_free(pRSAPriKey);
	fclose(hPriKeyFile);
	CRYPTO_cleanup_all_ex_data();
	return strRet;
}
std::string DecodeRSAKeyFilePub(const std::string& strPemFileName, const std::string& strData)
{
	if (strPemFileName.empty() || strData.empty())
	{
		assert(false);
		return "";
	}
	FILE* hPriKeyFile = fopen(strPemFileName.c_str(), "rb");
	if (hPriKeyFile == NULL)
	{
		assert(false);
		return "";
	}
	std::string strRet;
	RSA* pRSAPriKey = RSA_new();
	if (PEM_read_RSA_PUBKEY(hPriKeyFile, &pRSAPriKey, 0, 0) == NULL)
	{
		assert(false);
		return "";
	}
	int nLen = RSA_size(pRSAPriKey);
	char* pDecode = new char[nLen + 1];
	int ret = RSA_public_decrypt(strData.length(), (const unsigned char*)strData.c_str(), (unsigned char*)pDecode, pRSAPriKey, RSA_PKCS1_PADDING);
	if (ret >= 0)
	{
		strRet = std::string((char*)pDecode, ret);
	}
	delete[] pDecode;
	RSA_free(pRSAPriKey);
	fclose(hPriKeyFile);
	CRYPTO_cleanup_all_ex_data();
	return strRet;
}
std::string DecodeRSAKeyPub(const std::string& strData)
{
	string strPublicKey(PublicKey);
	int nPublicKeyLen = strPublicKey.size();      //strPublicKey为base64编码的公钥字符串
	for (int i = 64; i < nPublicKeyLen; i += 64)
	{
		if (strPublicKey[i] != '\n')
		{
			strPublicKey.insert(i, "\n");
		}
		i++;
	}
	strPublicKey.insert(0, "-----BEGIN PUBLIC KEY-----\n");
	strPublicKey.append("\n-----END PUBLIC KEY-----\n");
	std::string strRet;
	BIO *bio = NULL;
	RSA *pRSAPriKey = NULL;
	char *chPublicKey = const_cast<char *>(strPublicKey.c_str()); // const_cast<char *>(strPublicKey);
	//BIO_read(bio, chPublicKey, strlen(pubKey));
	if ((bio = BIO_new_mem_buf(chPublicKey, -1)) == NULL)       //从字符串读取RSA公钥
	{
		cout << "BIO_new_mem_buf failed!" << endl;
	}
	pRSAPriKey = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);   //从bio结构中得到rsa结构

	int nLen = RSA_size(pRSAPriKey);
	char* pDecode = new char[nLen + 1];
	int ret = RSA_public_decrypt(strData.length(), (const unsigned char*)strData.c_str(), (unsigned char*)pDecode, pRSAPriKey, RSA_PKCS1_PADDING);
	if (ret >= 0)
	{
		strRet = std::string((char*)pDecode, ret);
	}
	delete[] pDecode;
	RSA_free(pRSAPriKey);
	CRYPTO_cleanup_all_ex_data();
	return strRet;
}
//
//int main()
//{
//	//原文
//	const string one = "skl;dfhas;lkdfhslk;dfhsidfhoiehrfoishfsidf";
//	cout << "one: " << one << endl;
//
//	//密文（二进制数据）
//	string two = EncodeRSAKeyFile("pubkey.pem", one);
//	cout << "two: " << two << endl;
//
//	//顺利的话，解密后的文字和原文是一致的
//	string three = DecodeRSAKeyFile("prikey.pem", two);
//	cout << "three: " << three << endl;
//	return 0;
//}