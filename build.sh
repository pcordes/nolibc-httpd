#!/bin/sh

#  -Wno-pedantic \
#  -mpreferred-stack-boundary=3 \  # 1160 with, 1152 without
#  -ffixed-r9 \  gcc only?
#  -ffunction-sections \
#    -mx32 \  908 bytes (GCC) with inline syscalls, 880 with clang
#  -Werror

#gcc -Os \
clang -Oz \
  -s -no-pie \
  -pedantic \
  -Wall \
  -std=gnu11 \
  -falign-functions=1 \
  -nostdlib \
  -ffreestanding \
  -fno-stack-protector \
  -fdata-sections \
  -fno-unwind-tables \
  -fno-asynchronous-unwind-tables \
  -Wl,-n \
  -Wl,--gc-sections \
  -Wl,--build-id=none \
  start.S httpd.c \
  -o httpd &&
strip -R .comment httpd
