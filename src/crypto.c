/* 
 * crypto.c -- The Atropates File Encryption Utility
 * Copyright (C) 2024 Indraj Gandham <hello@indraj.net>
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */


#define _POSIX_C_SOURCE 200809L

#define CHUNK_SIZE 2048
#define ENC_CHUNK_SIZE CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES

#include <sodium.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include "crypto.h"


void generate_key(const char *keyfile_path)
{
	FILE *file = fopen(keyfile_path, "w");
	if (file == NULL) {
		fprintf(stderr, "error: failed to open keyfile for writing\n");
		exit(EXIT_FAILURE);
	}

	unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];

	if (sodium_mlock(key, crypto_secretstream_xchacha20poly1305_KEYBYTES)
		!= 0) {
		fprintf(stderr, "error: failed to pin key to RAM\n");
		exit(EXIT_FAILURE);
	}

	puts("generating key...");
	crypto_secretstream_xchacha20poly1305_keygen(key);

	if (fwrite(
		key,
		1,
		crypto_secretstream_xchacha20poly1305_KEYBYTES,
		file
	) < crypto_secretstream_xchacha20poly1305_KEYBYTES) {
		fprintf(stderr, "error: keyfile write interrupted\n");
		exit(EXIT_FAILURE);
	}

	if (ferror(file) != 0) {
		fprintf(stderr, "error: failed to write keyfile\n");
		exit(EXIT_FAILURE);
	}

	if (fclose(file) != 0) {
		fprintf(stderr,
			"error: failed to close keyfile after writing\n");
		exit(EXIT_FAILURE);
	}

	if (sodium_munlock(key, crypto_secretstream_xchacha20poly1305_KEYBYTES)
		!= 0) {
		fprintf(stderr, "error: failed to zero out key in RAM\n");
		exit(EXIT_FAILURE);
	}

	puts("done: keyfile written to disk");
	return;
}


void encrypt_file(const char *keyfile_path, const char *file_path,
			const char *dst_path)
{
	crypto_secretstream_xchacha20poly1305_state state;
	unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
	unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	unsigned char buffer[CHUNK_SIZE];
	unsigned char enc_buffer[ENC_CHUNK_SIZE];
	unsigned long long enc_buffer_len;

	if (sodium_mlock(key, crypto_secretstream_xchacha20poly1305_KEYBYTES)
		!= 0) {
		fprintf(stderr, "error: failed to pin key to RAM\n");
		exit(EXIT_FAILURE);
	}

	if (sodium_mlock(header,
		crypto_secretstream_xchacha20poly1305_HEADERBYTES)
		!= 0) {
		fprintf(stderr, "error: failed to pin header to RAM\n");
		exit(EXIT_FAILURE);
	}

	if (sodium_mlock(buffer, CHUNK_SIZE) != 0) {
		fprintf(stderr,
			"error: failed to pin plaintext buffer to RAM\n");
		exit(EXIT_FAILURE);
	}

	puts("reading key...");
	FILE *file = fopen(keyfile_path, "r");
	if (file == NULL) {
		fprintf(stderr, "error: failed to open keyfile for reading\n");
		exit(EXIT_FAILURE);
	}

	if (fread(
		key,
		1,
		crypto_secretstream_xchacha20poly1305_KEYBYTES,
		file
	) < crypto_secretstream_xchacha20poly1305_KEYBYTES) {
		fprintf(stderr, "error: invalid keyfile\n");
		exit(EXIT_FAILURE);
	}

	if (ferror(file) != 0) {
		fprintf(stderr, "error: failed to read keyfile\n");
		exit(EXIT_FAILURE);
	}

	if (fclose(file) != 0) {
		fprintf(stderr,
			"error: failed to close keyfile after reading\n");
		exit(EXIT_FAILURE);
	}

	FILE *src_file = fopen(file_path, "r");
	if (src_file == NULL) {
		fprintf(stderr,
			"error: failed to open plaintext file for reading\n");
		exit(EXIT_FAILURE);
	}

	FILE *dst_file = fopen(dst_path, "w");
	if (dst_file == NULL) {
		fprintf(stderr,
			"error: failed to open ciphertext file for writing\n");
		exit(EXIT_FAILURE);
	}

	puts("encrypting file...");

	crypto_secretstream_xchacha20poly1305_init_push(&state, header, key);

	if (fwrite(
		header,
		1,
		crypto_secretstream_xchacha20poly1305_HEADERBYTES,
		dst_file
	) < crypto_secretstream_xchacha20poly1305_HEADERBYTES) {
		fprintf(stderr,
			"error: header write interrupted\n");
		exit(EXIT_FAILURE);
	}

	if (ferror(dst_file) != 0) {
		fprintf(stderr, "error: failed to write header\n");
		exit(EXIT_FAILURE);
	}

	bool done = false;
	do {
		size_t bytes_read = fread(buffer, 1, CHUNK_SIZE, src_file);
		if (ferror(src_file) != 0) {
			fprintf(stderr,
				"error: failed to read plaintext file\n");
			exit(EXIT_FAILURE);
		}
		if (feof(src_file) != 0) {
			crypto_secretstream_xchacha20poly1305_push(
				&state,
				enc_buffer,
				&enc_buffer_len,
				buffer,
				bytes_read,
				NULL,
				0,
				crypto_secretstream_xchacha20poly1305_TAG_FINAL
			);
			done = true;
		} else {

			crypto_secretstream_xchacha20poly1305_push(
				&state,
				enc_buffer,
				&enc_buffer_len,
				buffer,
				bytes_read,
				NULL,
				0,
				0
			);
		}

		if (fwrite(enc_buffer, 1, enc_buffer_len, dst_file)
				< enc_buffer_len) {
			fprintf(stderr,
				"error: ciphertext write interrupted\n");
			exit(EXIT_FAILURE);
		}

		if (ferror(dst_file) != 0) {
			fprintf(stderr,
				"error: failed to write ciphertext file\n");
			exit(EXIT_FAILURE);
		}

	} while (!done);

	if (fclose(src_file) != 0) {
		fprintf(stderr,
		"error: failed to close plaintext file after reading\n");
		exit(EXIT_FAILURE);
	}

	if (fclose(dst_file) != 0) {
		fprintf(stderr,
		"error: failed to close ciphertext file after writing\n");
		exit(EXIT_FAILURE);
	}

	if (sodium_munlock(key, crypto_secretstream_xchacha20poly1305_KEYBYTES)
		!= 0) {
		fprintf(stderr, "error: failed to zero out key in RAM\n");
		exit(EXIT_FAILURE);
	}

	if (sodium_munlock(header,
		crypto_secretstream_xchacha20poly1305_HEADERBYTES)
		!= 0) {
		fprintf(stderr, "error: failed to zero out header in RAM\n");
		exit(EXIT_FAILURE);
	}

	if (sodium_munlock(buffer, CHUNK_SIZE) != 0) {
		fprintf(stderr,
			"error: failed to zero out plaintext buffer in RAM\n");
		exit(EXIT_FAILURE);
	}

	puts("done: ciphertext written to disk");

	return;
}


void decrypt_file(const char *keyfile_path, const char *file_path,
			const char *dst_path)
{
	crypto_secretstream_xchacha20poly1305_state state;
	unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
	unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	unsigned char buffer[CHUNK_SIZE];
	unsigned char enc_buffer[ENC_CHUNK_SIZE];
	unsigned char tag;
	unsigned long long buffer_len;

	if (sodium_mlock(key, crypto_secretstream_xchacha20poly1305_KEYBYTES)
		!= 0) {
		fprintf(stderr, "error: failed to pin key to RAM\n");
		exit(EXIT_FAILURE);
	}

	if (sodium_mlock(header,
		crypto_secretstream_xchacha20poly1305_HEADERBYTES)
		!= 0) {
		fprintf(stderr, "error: failed to pin header to RAM\n");
		exit(EXIT_FAILURE);
	}

	if (sodium_mlock(buffer, CHUNK_SIZE) != 0) {
		fprintf(stderr,
			"error: failed to pin plaintext buffer to RAM\n");
		exit(EXIT_FAILURE);
	}

	if (sodium_mlock(&tag, sizeof(unsigned char)) != 0) {
		fprintf(stderr, "error: failed to pin tag to RAM\n");
		exit(EXIT_FAILURE);
	}

	puts("reading key...");
	FILE *file = fopen(keyfile_path, "r");
	if (file == NULL) {
		fprintf(stderr, "error: failed to open keyfile for reading\n");
		exit(EXIT_FAILURE);
	}

	if (fread(
		key,
		1,
		crypto_secretstream_xchacha20poly1305_KEYBYTES,
		file
	) < crypto_secretstream_xchacha20poly1305_KEYBYTES) {
		fprintf(stderr, "error: invalid keyfile\n");
		exit(EXIT_FAILURE);
	}

	if (ferror(file) != 0) {
		fprintf(stderr, "error: failed to read keyfile\n");
		exit(EXIT_FAILURE);
	}

	if (fclose(file) != 0) {
		fprintf(stderr,
			"error: failed to close keyfile after reading\n");
		exit(EXIT_FAILURE);
	}

	FILE *src_file = fopen(file_path, "r");
	if (src_file == NULL) {
		fprintf(stderr,
			"error: failed to open ciphertext file for reading\n");
		exit(EXIT_FAILURE);
	}

	FILE *dst_file = fopen(dst_path, "w");
	if (dst_file == NULL) {
		fprintf(stderr,
			"error: failed to open plaintext file for writing\n");
		exit(EXIT_FAILURE);
	}

	puts("decrypting file...");

	if (fread(
		header,
		1,
		crypto_secretstream_xchacha20poly1305_HEADERBYTES,
		src_file
	) < crypto_secretstream_xchacha20poly1305_HEADERBYTES) {
		fprintf(stderr,
			"error: ciphertext file does not contain a header\n");
		exit(EXIT_FAILURE);
	}

	if (ferror(src_file) != 0) {
		fprintf(stderr, "error: failed to read ciphertext file\n");
		exit(EXIT_FAILURE);
	}

	if (crypto_secretstream_xchacha20poly1305_init_pull(
		&state,
		header,
		key
	) != 0) {
		fprintf(stderr,
			"error: got invalid header from ciphertext file\n");
		exit(EXIT_FAILURE);
	}

	bool done = false;
	do {
		size_t bytes_read = fread(enc_buffer,
						1,
						ENC_CHUNK_SIZE,
						src_file);
		if (ferror(src_file) != 0) {
			fprintf(stderr,
				"error: failed to read ciphertext file\n");
			exit(EXIT_FAILURE);
		}

		if (crypto_secretstream_xchacha20poly1305_pull(
				&state,
				buffer,
				&buffer_len,
				&tag,
				enc_buffer,
				bytes_read,
				NULL,
				0) != 0) {

			fprintf(stderr,
			"error: corrupt chunk detected\n");
			exit(EXIT_FAILURE);
		}

		if (feof(src_file) != 0) {

			if (tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
				fprintf(stderr,
				"error: final chunk was tagged incorrectly\n");
				exit(EXIT_FAILURE);
			}

			done = true;

		} else {

			if (tag != 0) {
				fprintf(stderr,
				"error: chunk was tagged incorrectly\n");
				exit(EXIT_FAILURE);
			}
		}

		if (fwrite(buffer, 1, buffer_len, dst_file)
				< buffer_len) {
			fprintf(stderr,
				"error: plaintext write interrupted\n");
			exit(EXIT_FAILURE);
		}

		if (ferror(dst_file) != 0) {
			fprintf(stderr,
				"error: failed to write plaintext file\n");
			exit(EXIT_FAILURE);
		}

	} while (!done);

	if (fclose(src_file) != 0) {
		fprintf(stderr,
		"error: failed to close ciphertext file after reading\n");
		exit(EXIT_FAILURE);
	}

	if (fclose(dst_file) != 0) {
		fprintf(stderr,
		"error: failed to close plaintext file after writing\n");
		exit(EXIT_FAILURE);
	}

	if (sodium_munlock(key, crypto_secretstream_xchacha20poly1305_KEYBYTES)
		!= 0) {
		fprintf(stderr, "error: failed to zero out key in RAM\n");
		exit(EXIT_FAILURE);
	}

	if (sodium_munlock(header,
		crypto_secretstream_xchacha20poly1305_HEADERBYTES)
		!= 0) {
		fprintf(stderr, "error: failed to zero out header in RAM\n");
		exit(EXIT_FAILURE);
	}

	if (sodium_munlock(buffer, CHUNK_SIZE) != 0) {
		fprintf(stderr,
			"error: failed to zero out plaintext buffer in RAM\n");
		exit(EXIT_FAILURE);
	}

	if (sodium_munlock(&tag, sizeof(unsigned char)) != 0) {
		fprintf(stderr, "error: failed to zero out tag in RAM\n");
		exit(EXIT_FAILURE);
	}

	puts("done: plaintext written to disk");

	return;
}
