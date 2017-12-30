//demo.cpp
// g++ demo.cpp -o demo -lcrypto
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include <iostream>
#include <string>
#include <cstring>
#include <cassert>
using namespace std;
const string PublicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHzOUy99dm5YfxvZyYMmxWiOwUdEpr / lBr3Bx9qIJ3OKI5iVXFyEyEojkwgb5201yslNHHHxYmOukF7X7569kj / bIRs32TdUFbEQeC8KxuM8n85dOXQgc185yOZK6XTaLTEbtEHNllig4uksFXtDf0bq6d6CtsBgY0W + cgZzgsmQIDAQAB";
//����
std::string EncodeRSAKeyFilePub(const std::string& strPemFileName, const std::string& strData);
std::string EncodeRSAKeyFilePri(const std::string& strPemFileName, const std::string& strData);
std::string EncodeRSAKeyPub(const std::string& strData);
int EncodeRSAKeyPubToFile(const std::string& strData, const std::string& saveFilename);
//����
std::string DecodeRSAKeyFilePri(const std::string& strPemFileName, const std::string& strData);
std::string DecodeRSAKeyFilePub(const std::string& strPemFileName, const std::string& strData);
std::string DecodeRSAKeyPub(const std::string& strData);
//
//int main()
//{
//	//ԭ��
//	const string one = "skl;dfhas;lkdfhslk;dfhsidfhoiehrfoishfsidf";
//	cout << "one: " << one << endl;
//
//	//���ģ����������ݣ�
//	string two = EncodeRSAKeyFile("pubkey.pem", one);
//	cout << "two: " << two << endl;
//
//	//˳���Ļ������ܺ�����ֺ�ԭ����һ�µ�
//	string three = DecodeRSAKeyFile("prikey.pem", two);
//	cout << "three: " << three << endl;
//	return 0;
//}