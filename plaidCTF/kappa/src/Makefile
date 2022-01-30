all: kappa

kappa: kappa.c
	i686-linux-gnu-gcc -m32 -std=c99 -w $^ -o $@
	strip $@

.PHONY: clean
clean:
	rm kappa

