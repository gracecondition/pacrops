CC = clang
CFLAGS = -arch arm64 -O0 -fno-stack-protector -Wno-deprecated-declarations -mbranch-protection=standard

all: demo

demo: demo.c
	$(CC) $(CFLAGS) -o demo demo.c

clean:
	rm -f demo
