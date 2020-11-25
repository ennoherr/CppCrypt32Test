#pragma comment(lib, "crypt32.lib")

#include <stdio.h>
#include <windows.h>
#include <Wincrypt.h>
#include <string>

//#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

void MyHandleError(char* s)
{
	fprintf(stderr, "An error occurred in running the program. \n");
	fprintf(stderr, "%s\n", s);
	fprintf(stderr, "Error number %x.\n", GetLastError());
	fprintf(stderr, "Program terminating. \n");
}


std::string EncryptCryptApiToHex(std::string to_encrypt)
{
	if (to_encrypt.length() == 0 || to_encrypt.length() > 15)
	{
		return std::string();
	}

	DATA_BLOB DataIn = { 0 };
	DATA_BLOB DataOut = { 0 };
	DataIn.pbData = (BYTE*)to_encrypt.c_str();
	DataIn.cbData = (DWORD)strlen((char*)DataIn.pbData) + 1;

	std::string res = "";

	try
	{
		if (CryptProtectData(&DataIn, NULL, NULL, NULL, NULL, CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN, &DataOut))
		{
			for (DWORD i = 0; i < DataOut.cbData; i++) {
				char temp[3] = "";
				sprintf_s(temp, "%02X", DataOut.pbData[i]);
				res += temp;
			}
		}

		LocalFree(DataIn.pbData);
		LocalFree(DataOut.pbData);

	}
	catch (const std::exception& e)
	{
		printf(e.what());
	}

	return res;
}

std::string DecryptCryptApiFromHex(std::string to_decrypt)
{
	char tmpDec[1024] = "";
	int len = 0;

	memset(tmpDec, 1024, 0);

	try
	{
		for (size_t i = 0; i < to_decrypt.length(); i += 2)
		{
			char tmpSrc[3] = "";
			tmpSrc[0] = to_decrypt.at(i);
			tmpSrc[1] = to_decrypt.at(i + (size_t)1);
			tmpSrc[2] = 0;

			char tmpDst = (char)strtol(tmpSrc, NULL, 16);

			tmpDec[len++] = tmpDst;
		}
	}
	catch (const std::exception& e)
	{
		printf(e.what());
	}

	DATA_BLOB DataIn = { 0 };
	DATA_BLOB DataOut = { 0 };
	DataIn.pbData = (BYTE*)tmpDec;
	DataIn.cbData = len;

	std::string res = "";

	try
	{
		if (CryptUnprotectData(&DataIn, NULL, NULL, NULL, NULL, CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN, &DataOut))
		{
			res = (char*)DataOut.pbData;
		}

		LocalFree(DataIn.pbData);
		LocalFree(DataOut.pbData);
	}
	catch (const std::exception& e)
	{
		printf(e.what());
	}

	return res;
}


int main()
{
	std::string text = "123456789012345";

	std::string enc = EncryptCryptApiToHex(text);
	std::string dec = DecryptCryptApiFromHex(enc);
	
	printf("\r\n");
	printf(enc.c_str());
	printf("\r\n");
	printf(dec.c_str());
	printf("\r\n");


	return 0;
}
