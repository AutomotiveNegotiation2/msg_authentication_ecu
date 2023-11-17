#create library file 

  $> cmake -S . -B build
  $> cd build 
  $> make
  $> ls ./output/libatmcrypto.a
    libatmcrypto.a

# create executable file
  $> mkdir output  // if not exist
  $> make
  $> ls ./output/run_main
    run_main 

  $> cd output
  $> sudo ./run_main
	rsa encrypt success
	rsa decrypt success
	rsa signed success
	rsa verify success

## 내부에서PRNG알고리즘을 사용하며 
 Linux System에 의존적입니다.
