#!/bin/bash

gcc -g3 -O0 -o test_aes_ctr  test/test_suite_cipher.aes_ctr.c cipher.c cipher_wrap.c aes.c padlock.c camellia.c  -Iinclude 
