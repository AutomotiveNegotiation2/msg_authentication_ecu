#!/bin/bash

gcc -g3 -O0 -o test_aes_ctr  test_suite_cipher.aes_ctr.c ./library/cipher.c ./library/cipher_wrap.c ./library/aes.c ./library/padlock.c  ./library/camellia.c  -Iinclude  && ./test_aes_ctr
