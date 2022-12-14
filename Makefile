crow_compile:
	g++ crow_main.cpp openssl_ecdh.cpp aes.cpp -lssl -lcrypto -o crow_main
echo_hello:
	echo "hello"
