#!/bin/bash

DIR=output

run:
	@if  [ ! -d $(DIR) ]; then \
		mkdir $(DIR); \
	fi
	gcc -Wall -O0 -g3 main.c -I inc -o ./$(DIR)/run_main -L ./build/$(DIR)  -latmcrypto

dummy:


clean:
	@if [ -d $(DIR) ]; then \
		rm -r $(DIR); \
	fi
	
