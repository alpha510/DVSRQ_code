#ifndef _ALGO_HMAC_H_
#define _ALGO_HMAC_H_
#include <iostream>
#include <string.h>
#include <stdio.h>
#pragma warning(disable : 4996)
using namespace std;
int HmacEncode(const char * algo,
	const char * key, unsigned int key_length,
	const char * input, unsigned int input_length,
	unsigned char * &output, unsigned int &output_length);

std::string HmacEncode_rs(const char* algo, string key, string input);

#endif
