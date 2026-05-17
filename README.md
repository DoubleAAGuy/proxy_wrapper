# proxy_wrapper

Forces any Windows executable (and its child processes) to route all TCP connections through a SOCKS5 proxy — no configuration needed inside the target app.

Works by injecting `socks_hook.dll` into the target process, which hooks Winsock's `connect()` and `WSAConnect()` (covers both native and .NET apps) and `CreateProcessW/A` (automatically injects the hook into child processes) via inline trampolines.

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
2. Injects `socks_hook.dll` via `CreateRemoteThread` + `LoadLibraryA`
3. The DLL installs inline trampoline hooks on:
   - `connect()` — native C/C++ apps
   - `WSAConnect()` — .NET applications (PowerShell, C#, etc.)
   - `CreateProcessW/A` — automatic DLL injection into child processes
4. Target resumes — every TCP connection is intercepted, a SOCKS5 CONNECT handshake is performed through the proxy, and traffic flows transparently
5. When the target spawns child processes (e.g., powershell.exe spawning curl.exe), the hook DLL is automatically injected into them too

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
- The SOCKS5 proxy must support `CONNECT` with no authentication
- Architecture mismatch between parent and child processes is not handled (e.g., 64-bit parent spawning 32-bit child)
