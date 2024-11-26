#include "algo_hmac.h"
#include <openssl/hmac.h>
#include <string.h>
#include <iostream>
using namespace std;

string HmacEncode_rs(const char* algo, string key, string input) {
	const EVP_MD* engine = NULL;
	if (strcasecmp("sha512", algo) == 0) {
		engine = EVP_sha512();
	}
	else if (strcasecmp("sha256", algo) == 0) {
		engine = EVP_sha256();
	}
	else if (strcasecmp("sha1", algo) == 0) {
		engine = EVP_sha1();
	}
	else if (strcasecmp("md5", algo) == 0) {
		engine = EVP_md5();
	}
	else if (strcasecmp("sha224", algo) == 0) {
		engine = EVP_sha224();
	}
	else if (strcasecmp("sha384", algo) == 0) {
		engine = EVP_sha384();
	}
	else {
		cout << "Algorithm " << algo << " is not supported by this program!" << endl;
		return "erro";
	}

	unsigned char* output = (unsigned char*)malloc(EVP_MAX_MD_SIZE);
	//char* char_key = new char[key.size() + 1]();
	//strcpy(char_key, key.c_str());

	//char* char_input = new char[input.size() + 1]();
	//strcpy(char_input, input.c_str());

	unsigned int output_length = 0;
	
	char* char_key = new char[key.size() + 1]();
	strcpy(char_key, key.c_str());

	char* char_input = new char[input.size() + 1]();
	strcpy(char_input, input.c_str());


	output = (unsigned char*)malloc(EVP_MAX_MD_SIZE);


	HMAC_CTX* ctx = HMAC_CTX_new();
	HMAC_CTX_reset(ctx);
	HMAC_Init_ex(ctx, char_key, key.size(), engine, NULL);
	HMAC_Update(ctx, (unsigned char*)char_input, input.size());	// input is OK; &input is WRONG !!!

	HMAC_Final(ctx, output, &output_length);
	HMAC_CTX_free(ctx);

	char res[output_length * 2 + 1];
//	char res[output_length * 2];
	for (int i = 0; i < output_length; ++i)
	{
		sprintf(&res[i * 2], "%02x", output[i]);
	}
	
//	return string(res, output_length * 2 + 1);
	return string(res, output_length * 2);


}




int HmacEncode(const char * algo, 
		const char * key, unsigned int key_length, 
		const char * input, unsigned int input_length, 
		unsigned char * &output, unsigned int &output_length) {
	const EVP_MD * engine = NULL;
	if(strcasecmp("sha512", algo) == 0) {
		engine = EVP_sha512();
	}
	else if(strcasecmp("sha256", algo) == 0) {
		engine = EVP_sha256();
	}
	else if(strcasecmp("sha1", algo) == 0) {
		engine = EVP_sha1();
	}
	else if(strcasecmp("md5", algo) == 0) {
		engine = EVP_md5();
	}
	else if(strcasecmp("sha224", algo) == 0) {
		engine = EVP_sha224();
	}
	else if(strcasecmp("sha384", algo) == 0) {
		engine = EVP_sha384();
	}
	else {
		cout << "Algorithm " << algo << " is not supported by this program!" << endl;
		return -1;
	}

	output = (unsigned char*)malloc(EVP_MAX_MD_SIZE);
	
	HMAC_CTX* ctx = HMAC_CTX_new();
	HMAC_CTX_reset(ctx);
	HMAC_Init_ex(ctx, key, strlen(key), engine, NULL);
	HMAC_Update(ctx, (unsigned char*)input, strlen(input));	// input is OK; &input is WRONG !!!

	HMAC_Final(ctx, output, &output_length);
	HMAC_CTX_free(ctx);	

	char res[output_length * 2 + 1];
	for (int i = 0; i < output_length; ++i)
	{
		sprintf(&res[i * 2], "%02x", output[i]);
	}
	cout<<string(res, output_length * 2 + 1)<<endl;

	return 0;
}

