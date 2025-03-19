/* 
 * crypto.h -- The Atropates File Encryption Utility
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

#ifndef ATROPATES_CRYPTO_H
#define ATROPATES_CRYPTO_H


void generate_key(const char *keyfile_path);
void encrypt_file(const char *keyfile_path, const char *file_path,
			const char *dst_path);

void decrypt_file(const char *keyfile_path, const char *file_path,
			const char *dst_path);


#endif
