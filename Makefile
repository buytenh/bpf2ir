all:		bpf2ir dofilter

clean:
		rm -f bpf2ir
		rm -f dofilter
		rm -f dofilter.bc
		rm -f dofilter.ll
		rm -f filter.ll

bpf2ir:		bpf2ir.c
		gcc -Wall -o bpf2ir bpf2ir.c

filter.ll:	bpf2ir filter.wtf
		./bpf2ir < filter.wtf > filter.ll

dofilter:	dofilter.ll filter.ll
		clang -O4 -flto -m32 -o dofilter dofilter.ll filter.ll

dofilter.ll:	dofilter.bc
		llvm-dis -o dofilter.ll dofilter.bc

dofilter.bc:	dofilter.c
		clang -O4 -c -emit-llvm -flto -m32 -o dofilter.bc dofilter.c
