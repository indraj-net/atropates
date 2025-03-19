/* 
 * main.c -- The Atropates File Encryption Utility
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

#define VERSION 1
#define REVISION 1

#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <sodium.h>

#include "crypto.h"


int main(int argc, char **argv)
{
	printf("The Atropates File Encryption Utility, v%d rev%d\n"
		"Copyright (C) 2024 Indraj Gandham\n"
		"This software comes with ABSOLUTELY NO WARRANTY; "
		"see COPYING for details.\n\n", VERSION, REVISION);

	if (argc > 5) {
		fprintf(stderr, "error: too many arguments\n");
		return EXIT_FAILURE;
	} else if (argc < 2) {
		fprintf(stderr, "error: too few arguments\n");
		return EXIT_FAILURE;
	}

	bool valid_arg = false;

	if (strcmp(argv[1], "--help") == 0) {
		if (argc != 2) {
			fprintf(stderr,
			"error: option --help takes no arguments\n");
			return EXIT_FAILURE;
		}
		printf("Usage: %s <KEYFILE> --OPTION <SRC> <DST>\n", argv[0]);
		return EXIT_SUCCESS;
	}

	if (strcmp(argv[2], "--generate") == 0) {
		valid_arg = true;
		if (argc != 3) {
			fprintf(stderr,
			"error: option --generate takes exactly 2 arguments\n");
			return EXIT_FAILURE;
		}
	}

	if (strcmp(argv[2], "--encrypt") == 0) {
		valid_arg = true;
		if (argc != 5) {
			fprintf(stderr,
			"error: option --encrypt takes exactly 4 arguments\n");
			return EXIT_FAILURE;
		}
	}

	if (strcmp(argv[2], "--decrypt") == 0) {
		valid_arg = true;
		if (argc != 5) {
			fprintf(stderr,
			"error: option --decrypt takes exactly 4 arguments\n");
			return EXIT_FAILURE;
		}
	}

	if (!valid_arg) {
		fprintf(stderr, "error: unrecognised option\n");
		return EXIT_FAILURE;
	}

	if (sodium_init() < 0) {
		fprintf(stderr, "error: failed to initialise libsodium\n");
		return EXIT_FAILURE;
	}

	struct stat status;
	if (stat(argv[1], &status) == 0) {

		if (strcmp(argv[2], "--generate") == 0) {
			fprintf(stderr, "error: keyfile exists\n");
			return EXIT_FAILURE;
		}

		if (S_ISREG(status.st_mode) == 0) {
			fprintf(stderr,
				"error: keyfile is not a regular file\n");
				return EXIT_FAILURE;
		}

	} else {

		if (errno == ENOENT) {
			if (strcmp(argv[2], "--generate") == 0) {
				generate_key(argv[1]);
				return EXIT_SUCCESS;
			} else {
				fprintf(stderr,
					"error: keyfile does not exist\n");
				return EXIT_FAILURE;
			}

		} else {
			fprintf(stderr, "error: failed to stat() keyfile\n");
			return EXIT_FAILURE;
		}
	}

	if (stat(argv[3], &status) == 0) {
		if (S_ISREG(status.st_mode) == 0) {
			fprintf(stderr,
				"error: source file is not a regular file\n");
			return EXIT_FAILURE;
		}

	} else {
		if (errno == ENOENT) {
			fprintf(stderr, "error: source file does not exist\n");
			return EXIT_FAILURE;
		} else {
			fprintf(stderr,
				"error: failed to stat() source file\n");
			return EXIT_FAILURE;
		}
	}

	if (stat(argv[4], &status) == 0) {
		fprintf(stderr, "error: destination file exists\n");
		return EXIT_FAILURE;
	} else {
		if (errno != ENOENT) {
			fprintf(stderr,
				"error: failed to stat() destination file\n");
			return EXIT_FAILURE;
		}
	}

	if (strcmp(argv[2], "--encrypt") == 0) {
		encrypt_file(argv[1], argv[3], argv[4]);
	} else if (strcmp(argv[2], "--decrypt") == 0) {
		decrypt_file(argv[1], argv[3], argv[4]);
	}

	return EXIT_SUCCESS;
}
