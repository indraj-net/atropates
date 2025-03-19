# 
# Makefile -- The Atropates File Encryption Utility
# Copyright (C) 2024 Indraj Gandham <hello@indraj.net>
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# 
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#


CC := gcc

DEBUG := -g3 -fno-omit-frame-pointer

RELEASE := -s \
-fno-delete-null-pointer-checks \
-fno-strict-aliasing \
-ftrivial-auto-var-init=zero

ELF_HARDEN := -fPIE
SO_HARDEN := -fPIC -shared

AMD64_HARDEN := -fcf-protection=full
AARCH64_HARDEN := -mbranch-protection=standard
PTHREADS_HARDEN := -fexceptions

DISALLOW_OBSOLETE_HARDEN := -Werror=implicit \
-Werror=incompatible-pointer-types \
-Werror=int-conversion
 
HARDEN := -Wformat \
-Wformat=2 \
-Wconversion \
-Wimplicit-fallthrough \
-Werror=format-security \
-Wtrampolines \
-Wbidi-chars=any,ucn \
-U_FORTIFY_SOURCE \
-D_FORTIFY_SOURCE=3 \
-D_GLIBCXX_ASSERTIONS \
-fstrict-flex-arrays=3 \
-fstack-clash-protection \
-fstack-protector-strong
 
LD_HARDEN := -pie \
-Wl,-z,nodlopen \
-Wl,-z,noexecstack \
-Wl,-z,relro \
-Wl,-z,now \
-Wl,--as-needed \
-Wl,--no-copy-dt-needed-entries
 
CFLAGS := -O2 \
-Werror \
-Wextra \
-Wall \
-std=c99 \
-pedantic-errors
 
ELF_AMD64_HARDEN := $(ELF_HARDEN) \
$(AMD64_HARDEN) \
$(DISALLOW_OBSOLETE_HARDEN) \
$(HARDEN) \
$(PTHREADS_HARDEN)

ELF_AARCH64_HARDEN := $(ELF_HARDEN) \
$(AARCH64_HARDEN) \
$(DISALLOW_OBSOLETE_HARDEN) \
$(HARDEN) \
$(PTHREADS_HARDEN)

SO_AMD64_HARDEN := $(SO_HARDEN) \
$(AMD64_HARDEN) \
$(DISALLOW_OBSOLETE_HARDEN) \
$(HARDEN) \
$(PTHREADS_HARDEN)

SO_AARCH64_HARDEN := $(SO_HARDEN) \
$(AARCH64_HARDEN) \
$(DISALLOW_OBSOLETE_HARDEN) \
$(HARDEN) \
$(PTHREADS_HARDEN)

LDFLAGS := -lsodium
OUT := atropates
CONFIG := $(CFLAGS) $(RELEASE) $(ELF_AMD64_HARDEN)

OBJS := $(patsubst src/%.c, obj/%.o, $(wildcard src/*.c))

.PHONY: all clean
all: $(OUT)

clean:
	rm -rf $(OUT) obj/*.o

$(OUT): $(OBJS)
	$(CC) $(CONFIG) $(LD_HARDEN) -o $(OUT) $(OBJS) $(LDFLAGS)

obj/main.o: src/main.c src/crypto.h
	$(CC) $(CONFIG) -c src/main.c -o obj/main.o

obj/crypto.o: src/crypto.c src/crypto.h
	$(CC) $(CONFIG) -c src/crypto.c -o obj/crypto.o
