

all:
	g++ -std=c++17 sample_http_client.cpp sample_tls_crypto.cpp -o http_client -lssl -lcrypto

	g++ -g -O0 -Wall -msse2 -msse -march=native -maes intrinsics.cpp -o intrinsics

	g++ ossl.cpp ossl-test.cpp -o ossl -lssl -lcrypto
	g++ ossl-sample.cpp -o ossl-sample -lssl -lcrypto
