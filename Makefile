CC_X64 := x86_64-w64-mingw32-gcc
CC_X86 := i686-w64-mingw32-gcc
CFLAGS := -Os -s -Wall -Wextra

all: x64 x86

x64: build_x64/proxy_wrapper.exe build_x64/socks_hook.dll
x86: build_x86/proxy_wrapper.exe build_x86/socks_hook.dll

build_x64/proxy_wrapper.exe: proxy_wrapper.c | build_x64
	$(CC_X64) $(CFLAGS) -o $@ proxy_wrapper.c

build_x64/socks_hook.dll: socks_hook.c | build_x64
	$(CC_X64) $(CFLAGS) -shared -o $@ socks_hook.c -lws2_32

build_x86/proxy_wrapper.exe: proxy_wrapper.c | build_x86
	$(CC_X86) $(CFLAGS) -o $@ proxy_wrapper.c

build_x86/socks_hook.dll: socks_hook.c | build_x86
	$(CC_X86) $(CFLAGS) -shared -o $@ socks_hook.c -lws2_32

build_x64 build_x86:
	mkdir -p $@

clean:
	rm -rf build_x64 build_x86

.PHONY: all x64 x86 clean
