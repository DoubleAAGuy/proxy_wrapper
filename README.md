# proxy_wrapper

Forces any Windows executable to route all TCP connections through a SOCKS5 proxy — no configuration needed inside the target app.

Works by injecting `socks_hook.dll` into the target process, which hooks Winsock's `connect()` via an inline trampoline and redirects through the SOCKS5 proxy.

## Usage

```cmd
proxy_wrapper.exe -proxy=IP:PORT -target=PATH [target args...]
```

### Examples

```cmd
proxy_wrapper.exe -proxy=127.0.0.1:1080 -target=chrome.exe
proxy_wrapper.exe -proxy=192.168.1.50:9050 -target="C:\Program Files\Firefox\firefox.exe"
proxy_wrapper.exe -proxy=10.0.0.1:1080 -target=powershell.exe -Command "curl.exe http://api.ipify.org"
```

## How it works

1. `proxy_wrapper.exe` launches the target in a **suspended** state
2. Allocates memory in the target and injects `socks_hook.dll` via `CreateRemoteThread` + `LoadLibraryA`
3. The DLL installs an **inline trampoline hook** on `connect()` in `ws2_32.dll`
4. Target resumes — every `connect()` call is intercepted, a SOCKS5 CONNECT handshake is performed through the proxy, and traffic flows transparently

## Downloads

Pre-built binaries are available in the [Releases](https://github.com/DoubleAAGuy/proxy_wrapper/releases) page.

| Archive | Architecture |
|---------|-------------|
| `proxy_wrapper_x64.zip` | 64-bit (x86_64) |
| `proxy_wrapper_x86.zip` | 32-bit (x86) |

Each zip contains:
- `proxy_wrapper.exe` — the launcher
- `socks_hook.dll` — the hook DLL (must be in the same directory)

## Building from source

Requires [mingw-w64](https://www.mingw-w64.org/).

```bash
# Build both architectures
make

# Build only 64-bit
make x64

# Build only 32-bit
make x86
```

## Limitations

- Both `proxy_wrapper.exe` and `socks_hook.dll` must match the target process's bitness (x64 for 64-bit apps, x86 for 32-bit apps)
- Only TCP connections via `connect()` are hooked; `WSAConnect` is not yet intercepted
- The SOCKS5 proxy must support `CONNECT` with no authentication
