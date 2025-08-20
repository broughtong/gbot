FLAGS = -O3 -std=c++23



all:
	g++-15 $(FLAGS) -Idpdk/config -Idpdk/lib/eal/include -Ldpdk/build/lib src/main.cpp src/arp.cpp -o app
