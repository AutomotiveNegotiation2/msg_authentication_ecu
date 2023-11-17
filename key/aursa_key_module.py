import os
from Crypto.PublicKey import RSA

#generate Key pair ras 2048bit
def GenKey():
	key = RSA.generate(2048)
	with open("private.pem", 'wb') as f:
		f.write(key.exportKey('PEM'))

	key = key.publickey()
	with open("public.pem", 'wb') as f:
		f.write(key.exportKey('PEM'))

def ExtractMyPubkey():
	with open("public.pem", 'rb') as f:
		key = RSA.importKey(f.read())

	h = (format (key.n, 'X'))
	strlen = len(h)
	rowcnt = strlen/32
	ix = 0


	# write modulus N
	with open("my_public.h", 'w') as f:
		f.write("const char* mypub_N = \n")
	with open("my_public.h", 'a') as f:
		while ix < strlen:
			rowcnt = rowcnt - 1
			if rowcnt > 0:
				f.write("\t\t\"" + h[ix:ix+32] + "\" \\\n")
			else : 
				f.write("\t\t\"" + h[ix:ix+32] + "\";\n" )
			ix = ix + 32

	# write exponent
	with open("my_public.h", 'a') as f:
		f.write("\nconst char* mypub_E = \n")
		f.write("\t\t\"10001\";\n")


def ExtractMyPrvkey():
	with open("private.pem", 'rb') as f:
		key = RSA.importKey(f.read())

	# extract modulus N
	h = (format (key.n, 'X'))
	strlen	= len(h)
	rowcnt	= strlen/32
	ix		= 0
	with open("my_private.h", 'w') as f:
		f.write("const char* myprv_N = \n")
	with open("my_private.h", 'a') as f:
		while ix < strlen:
			rowcnt = rowcnt - 1
			if rowcnt > 0:
				f.write("\t\t\"" + h[ix:ix+32] + "\" \\\n")
			else : 
				f.write("\t\t\"" + h[ix:ix+32] + "\";\n" )
			ix = ix + 32

	# extract exponent
	with open("my_private.h", 'a') as f:
		f.write("\nconst char* myprv_E = \n")
		f.write("\t\t\"10001\";\n")

	# extract D
	h =(format (key.d, 'X'))
	strlen	= len(h)
	rowcnt	= strlen/32
	ix		= 0
	with open("my_private.h", 'a') as f:
		f.write("const char* myprv_D = \n")
	with open("my_private.h", 'a') as f:
		while ix < strlen:
			rowcnt	= rowcnt - 1
			if rowcnt > 0:
				f.write("\t\t\"" + h[ix:ix+32] + "\" \\\n")
			else :
				f.write("\t\t\"" + h[ix:ix+32] + "\";\n" )
			ix = ix + 32

if __name__ == '__main__':
	GenKey()
	ExtractMyPubkey()
	ExtractMyPrvkey()
