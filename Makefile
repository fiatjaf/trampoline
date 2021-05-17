trampoline: $(shell find . -name "*.v")
	v -o trampoline.c .
	musl-clang -std=gnu99 -o trampoline -static trampoline.c
