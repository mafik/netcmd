all : a.out

a.out : *.cc *.hh
	clang++-17 -std=c++2b -g -O0 *.cc -lssl -lcrypto

debug : a.out
	sudo gdb ./a.out -q -ex run

run : a.out
	sudo ./a.out
