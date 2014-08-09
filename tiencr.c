/*
 * The MIT License (MIT)
 * 
 * Copyright (c) 2014 Marek Roszko
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>
#include <stdint.h>

#ifdef _WIN32
typedef int bool;
#define false 0
#define true 1
#endif

#define HEADER_LEN 13
#define ERR_MEMORY 1
#define ERR_FILE_IO 2
#define ERR_FILE_READ 3

char encode_char(char* key, size_t key_len, char input_char, size_t* i);
void xor_key(char* key, size_t len, bool dir);

//const char* ti_default_key = "DefaultChemIDVerificationToolKey-32BitsShowsPatternsinTheOutputFileSoIncreasingTheSizeTo>100,LetSizeBe =107";


const char header_str_bytes[] = {'T','I','E','N','C','R'};

int main()
{
	int ret = 0;
	FILE *fp = NULL;
	uint8_t header[HEADER_LEN] = {0};
	size_t encode_index = 0;
	size_t key_len = 0;
	char* buf_ptr;
	char* key_buf;
	size_t i = 0;
	char* buffer;
	size_t  file_size;
	size_t res;

	fp = fopen("test.encr","rb");

	if( fp == NULL )
	{
		printf("Error opening .encr file\n");
		ret = ERR_FILE_IO;
		goto err;
	}
	
	/* Get file size */
	fseek(fp,0,SEEK_END);
	file_size = ftell(fp);

	buffer = (char*)malloc(file_size);
	buf_ptr = buffer;
	
	/* Back to the header */
	fseek(fp,0x00,SEEK_SET);
	res = fread(header,HEADER_LEN,1,fp);

	if( res != 1 )
	{
		printf("File error:Unable to read header data\n");
		ret = ERR_FILE_READ;
		goto err;
	}

	/* verify the header */
	for(i = 0; i < sizeof(header_str_bytes); i++ )
	{
		if(header_str_bytes[i] != header[i])
		{
			printf("File error:File is not valid\n");
			ret = ERR_FILE_READ;
			goto err;
		}
	}

	/* Key length byte is at byte 0x0d(it's xored) */
	fread(header,1,1,fp);
	if( res != 1 )
	{
		printf("File error:Unable to read header data\n");
		ret = ERR_FILE_READ;
		goto err;
	}

	/* Get the original key len by xoring byte 0x0d with byte 0x07 */
	key_len = header[0] ^ header[7];

	/* Grab the key which is next */
	key_buf = (char *)malloc(key_len);
	if( key_buf == NULL )
	{
		ret = ERR_MEMORY;
		goto err;
	}

	res = fread(key_buf,1,key_len,fp);
	xor_key(key_buf, key_len, 1);

	/* Read and decode to buffer */
	while(!feof(fp))
	{
		res = fread(buf_ptr,1,1,fp);
		if( res != 1 )
		{
			ret = ERR_FILE_READ;
			goto err;
		}
	
		*buf_ptr = encode_char(key_buf, key_len, *buf_ptr, &encode_index);
		printf("%x", *buf_ptr);
		buf_ptr++;
	}

	getch();
err:
	free(buffer);
	free(key_buf);
	return ret;
}

void xor_key(char* key, size_t len, bool dir)
{
	size_t i = 0;
	char* original_key = (char *)malloc(len);
	memcpy(original_key, key, len);

	if( dir )
	{
		for( i = 1; i < len; ++i )
			key[i] ^= original_key[i-1];
	}
	else
	{
		for( i = len-1; len > 0; --len )
			key[i] ^= original_key[i-1];
	}
}

char encode_char(char* key, size_t key_len, char input_char, size_t* i)
{
	char current_key_char = key[*i];
	(*i)++;

	if( *i == key_len)
	{
		*i = 0;
	}

	return input_char ^ current_key_char;
}