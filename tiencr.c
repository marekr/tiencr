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
#include <stdint.h>
#include <time.h>

#ifdef _WIN32
#include "getopt.h"

typedef int bool;
#define false 0
#define true 1
#endif

#define VERSION_MAJOR	0
#define VERSION_MINOR	1

#define ENCRYPT_KEY_SIZE 12
#define HEADER_LEN 13
#define ERR_NONE		0
#define ERR_ARGS		1
#define ERR_MEMORY		2
#define ERR_FILE_IO		3
#define ERR_FILE_READ	4

int read_encr(const char* file_path, uint8_t** buffer, size_t* size);
int read_file_to_buffer(const char* file_path, uint8_t** buffer, size_t* buf_size);
int write_buffer(const char* file_path, uint8_t* buffer, size_t buf_size);
int write_buffer_as_encr(const char* file_path, uint8_t* buffer, size_t buf_size);
char encode_char(uint8_t* key, size_t key_len, char input_char, size_t* i);
void xor_key(uint8_t* key, size_t len, bool dir);
void populate_key(uint8_t* key, size_t len);
void print_usage(void);

const char decrypted_ext[] = ".decrypted";
const char encrypted_ext[] = ".encr";
const char header_str_bytes[] = {'T','I','E','N','C','R'};

/*
 * \brief Application entry point
 *
 * \param argc
 * \param argv
 */
int main(int argc, char *argv[])
{
	int ret = 0;
	uint8_t* buffer = NULL;

	char* input_path = NULL;
	char* output_path = NULL;
	size_t encr_buffer_size = 0;

	bool decrypt = true;

	/*	process input args */
	
	int opt;
	while ((opt = getopt (argc, argv, "?hdei:o:")) != -1)
	{
		switch (opt)
		{
			case 'e':
				decrypt = false;
				break;
			case 'i':
				input_path = (char *)malloc(strlen(optarg)+1);
				strcpy(input_path, optarg);
				break;
			case 'o':
				output_path = (char *)malloc(strlen(optarg)+1);
				strcpy(output_path, optarg);
				break;
			case '?':
			case 'h':
				print_usage();
				return 0;
				break;
		}
	}

	if( input_path == NULL )
	{
		printf("Error: Input file not specified\n");
		ret = ERR_ARGS;
		goto err;
	}

	if( decrypt )
	{
		if( output_path == NULL )
		{
			output_path = (char *)malloc(strlen(input_path)+1+strlen(decrypted_ext));
			memset(output_path,0,strlen(input_path)+1+strlen(decrypted_ext));
			strcat(output_path,input_path);
			strcat(output_path,decrypted_ext);
		}
		ret = read_encr(input_path,&buffer,&encr_buffer_size);
		if( ret )
		{
			goto err;
		}

		ret = write_buffer(output_path, buffer, encr_buffer_size);
		if( !ret )
		{
			printf("Done\n");
		}
	}
	else
	{
		/* Seed rand for encryption */
		srand((unsigned int)time(NULL));

		if( output_path == NULL )
		{
			output_path = (char *)malloc(strlen(input_path)+1+strlen(encrypted_ext));
			memset(output_path,0,strlen(input_path)+1+strlen(encrypted_ext));
			strcat(output_path,input_path);
			strcat(output_path,encrypted_ext);
		}

		/* encrypt the file! */
		read_file_to_buffer(input_path, &buffer, &encr_buffer_size);
		write_buffer_as_encr(output_path, buffer, encr_buffer_size);
	}

err:
	free(output_path);
	free(input_path);

	return ret;
}

void print_usage(void)
{
	printf("tiencr version %d.%d\n", VERSION_MAJOR, VERSION_MINOR);
	printf("arguments:\n");
	printf("i - specifies input file\n");
	printf("d - decrypt the specified input file(default option and not required)\n");
	printf("e - encrypt the specified input file\n");
	printf("o - output file destination(defaults to input file name + .encr at the end)\n");
}

/*
 * \brief Read the contents of a file to a buffer and sets the passed in pointer to it
 *
 * \param file_path Path to file to read
 * \param buffer Pointer to buffer pointer that will be set once read is complete
 * \param buf_size Size of buffer once read is complete
 */
int read_file_to_buffer(const char* file_path, uint8_t** buffer, size_t* buf_size)
{
	int ret = 0;
	FILE *fp = NULL;
	size_t file_size;
	uint8_t* buf_ptr;

	fp = fopen(file_path,"rb");

	if( fp == NULL )
	{
		printf("Error opening .encr file\n");
		ret = ERR_FILE_IO;
		goto err;
	}
	
	fseek(fp,0,SEEK_END);
	file_size = ftell(fp);
	fseek(fp,0,SEEK_SET);

	if( !file_size )
	{
		ret = ERR_FILE_READ;
		goto err;
	}

	buf_ptr = (uint8_t *)malloc(file_size);
	if( buf_ptr == NULL )
	{
		ret= ERR_MEMORY;
		goto err;
	}

	ret = fread(buf_ptr, file_size, 1, fp);
	if( ret != 1 )
	{
		ret = ERR_FILE_READ;
		goto err;
	}

	*buffer = buf_ptr;
	*buf_size = file_size;
	
	fclose(fp);
	return ret;
err:
	free(buffer);
	fclose(fp);

	return ret;
}

/*
 * \brief Populate an array with random bytes, nothing special beyond that
 *
 * \param key Pointer to byte array
 * \param len Length of buffer
 */
void populate_key(uint8_t* key, size_t len)
{
	size_t i;

	for(i=0;i<len;i++)
	{
		key[i] = rand();
	}
}

/*
 * \brief Write out the specified buffer
 *
 * \param file_path Output file
 * \param buffer Pointer to byte buffer to write out
 * \param buf_size Size of buffer
 */
int write_buffer_as_encr(const char* file_path, uint8_t* buffer, size_t buf_size)
{
	int ret = 0;
	FILE *fp = NULL;
	uint8_t key_len_xor_val = rand();
	size_t encode_index = 0;

	uint8_t key[ENCRYPT_KEY_SIZE] = {0};
	uint8_t key_copy[ENCRYPT_KEY_SIZE] = {0};
	uint8_t key_len = ENCRYPT_KEY_SIZE;

	uint8_t dummy_buffer[10] = {0};
	size_t i = 0;

	populate_key(key,sizeof(key));
	memcpy(key_copy,key,sizeof(key));

	fp = fopen(file_path,"wb");

	if( fp == NULL )
	{
		printf("Error opening .encr file\n");
		ret = ERR_FILE_IO;
		goto err;
	}

	dummy_buffer[0] = 0x1;	//fixed
	dummy_buffer[1] = key_len_xor_val;
	dummy_buffer[7] = key_len ^ key_len_xor_val;

	fwrite(header_str_bytes,sizeof(header_str_bytes),1,fp);
	fwrite(dummy_buffer,8,1,fp);

	xor_key(key, key_len, true);
	fwrite(key,key_len,1,fp);

	for(i=0;i<buf_size;i++)
	{
		buffer[i] = encode_char(key_copy, key_len, buffer[i], &encode_index);
		fwrite(&buffer[i],1,1,fp);
	}

	fclose(fp);

err:
	fclose(fp);
	return ret;
}

/*
 * \brief Write out the specified buffer
 *
 * \param file_path Output file
 * \param buffer Pointer to byte buffer to write out
 * \param buf_size Size of buffer
 */
int write_buffer(const char* file_path, uint8_t* buffer, size_t buf_size)
{
	int ret = 0;
	FILE *fp = NULL;

	fp = fopen(file_path,"wb");

	if( fp == NULL )
	{
		printf("Error opening .encr file\n");
		ret = ERR_FILE_IO;
		goto err;
	}

	fwrite(buffer,1,buf_size,fp);

	fclose(fp);

err:
	fclose(fp);
	return ret;
}

/*
 * \brief Read's the specified encr file and returns a buffer with file size
 *
 * \param file_path Input file
 * \param buffer Pointer to byte buffer to return the allocated buffer to
 * \param size Size of buffer
 */
int read_encr(const char* file_path, uint8_t** buffer, size_t* size)
{
	int ret = 0;
	FILE *fp = NULL;
	uint8_t header[HEADER_LEN] = {0};
	size_t encode_index = 0;
	size_t key_len = 0;
	uint8_t* key_buf = NULL;
	size_t i = 0;
	size_t file_size;
	size_t res;
	uint8_t* buf_ptr = NULL;
	
	fp = fopen(file_path,"rb");

	if( fp == NULL )
	{
		printf("Error opening .encr file\n");
		ret = ERR_FILE_IO;
		goto err;
	}
	
	/* Get file size */
	fseek(fp,0,SEEK_END);
	file_size = ftell(fp);

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

	if (header[6] != 1)
	{
		printf("File error: Unsupported TIENCR format\n");
		ret = ERR_FILE_READ;
		goto err;
	}

	/* Key length byte is at byte 0x0d(it's xored) */
	res = fread(header,1,1,fp);
	if( res != 1 )
	{
		printf("File error:Unable to read header data\n");
		ret = ERR_FILE_READ;
		goto err;
	}

	/* Get the original key len by xoring byte 0x0d with byte 0x07 */
	key_len = header[0] ^ header[7];

	/* Grab the key which is next */
	key_buf = (uint8_t *)malloc(key_len);
	if( key_buf == NULL )
	{
		ret = ERR_MEMORY;
		goto err;
	}

	res = fread(key_buf,1,key_len,fp);
	xor_key(key_buf, key_len, false);
	
	file_size -= key_len;
	file_size -= 1;				/*key length byte */
	file_size -= HEADER_LEN;

	buf_ptr = (uint8_t*)malloc(file_size);


	/* Read and decode to buffer */
	i = 0;
	while(!feof(fp) && i < file_size)
	{
		res = fread(&buf_ptr[i],1,1,fp);
		if( res != 1 )
		{
			break;
		}
	
		buf_ptr[i] = encode_char(key_buf, key_len, buf_ptr[i], &encode_index);
		i++;
	}

	*buffer = buf_ptr;
	*size = file_size;
	goto ok;

err:
	free(buf_ptr);
ok:
	free(key_buf);
	if (fp != NULL)
	{
		fclose(fp);
	}
	return ret;
}

/*
 * \brief XOR's the data key back to its original form
 *
 * \param key Key data to be XORed
 * \param len Key length 
 * \param encrypt Encrypt or decrypt direction of the key
 */
void xor_key(uint8_t* key, size_t len, bool encrypt)
{
	size_t i = 0;

	if( encrypt )
	{
		for( i = 1; i < len; ++i )
			key[i] ^= key[i-1];
	}
	else
	{
		for( i = len-1; i > 0; --i )
			key[i] ^= key[i-1];
	}
}

/*
 * \brief Encodes/decodes a character using XOR and the key
 *
 * \param key Key data
 * \param len Key length 
 * \param input_char Input character
 * \param i Pointer to variable to track current position in key. 
 *			This must be used for consecutive data.
 */
char encode_char(uint8_t* key, size_t key_len, char input_char, size_t* key_index)
{
	char current_key_char = key[*key_index];
	(*key_index)++;

	if( *key_index == key_len)
	{
		*key_index = 0;
	}

	return input_char ^ current_key_char;
}