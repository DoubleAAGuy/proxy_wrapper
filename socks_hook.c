#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>

#define ENV_VAR "PROXY_WRAPPER_PROXY"
#define JMP_SIZE 5

typedef int (WINAPI *connect_t)(SOCKET, const struct sockaddr *, int);
typedef int (WINAPI *wsaconnect_t)(SOCKET, const struct sockaddr *, int,
    LPWSABUF, LPWSABUF, LPQOS, LPQOS);
typedef BOOL (WINAPI *createprocessw_t)(LPCWSTR, LPWSTR,
    LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD,
    LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *createprocessa_t)(LPCSTR, LPSTR,
    LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD,
    LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);

typedef struct { char host[256]; unsigned short port; } proxy_cfg_t;

static HMODULE g_dll;
static proxy_cfg_t g_cfg;
static struct sockaddr_in g_proxy_addr;
static int g_proxy_ready = 0;
static LONG g_in_create = 0;

static connect_t g_orig_connect;
static wsaconnect_t g_orig_wsaconnect;
static createprocessw_t g_orig_cpw;
static createprocessa_t g_orig_cpa;

static BYTE g_saved_conn[16]; static int g_saved_conn_n;
static BYTE g_saved_wsa[16];  static int g_saved_wsa_n;
static BYTE g_saved_cpw[16];  static int g_saved_cpw_n;
static BYTE g_saved_cpa[16];  static int g_saved_cpa_n;

static void *g_target_connect;
static void *g_target_wsaconnect;

// Returns total bytes consumed by ModRM [+SIB] [displacement] starting at code[off].
// Does NOT count the immediate.
static int modrm_off(BYTE *code, int off)
{
    BYTE mr = code[off];
    int mod = (mr >> 6) & 3;
    int rm = mr & 7;
    int total = 1;
    if (rm == 4 && mod != 3) {
        total++;
        BYTE sib = code[off + 1];
        int base = sib & 7;
        if (mod == 0 && base == 5) total += 4;
        else if (mod == 1) total++;
        else if (mod == 2) total += 4;
    } else {
        if (mod == 0 && rm == 5) total += 4;
        else if (mod == 1) total++;
        else if (mod == 2) total += 4;
    }
    return total;
}

#ifdef _WIN64
static int inst_len(BYTE *code)
{
    int o = 0;
    while (code[o] >= 0x40 && code[o] <= 0x4F) o++;
    BYTE b = code[o];

    if (b == 0x0F) {
        BYTE op2 = code[o + 1];
        if (op2 == 0x84 || op2 == 0x85 || op2 == 0x86 || op2 == 0x87 ||
            op2 == 0x8C || op2 == 0x8D || op2 == 0x8E || op2 == 0x8F)
            return o + 6;
        if (op2 == 0x1F) {
            BYTE mr = code[o + 2];
            int mod = (mr >> 6) & 3;
            if (mod == 0) return o + 3;
            if (mod == 1) return o + 4;
            if (mod == 2) return o + 7;
            return o + 2;
        }
        if (op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF)
            return o + 2 + modrm_off(code, o + 2);
        if ((op2 & 0xF0) == 0x40)  /* CMOVcc */
            return o + 2 + modrm_off(code, o + 2);
        if (op2 == 0xAF) /* IMUL */
            return o + 2 + modrm_off(code, o + 2);
        return 0;
    }

    /* MOV r/m,r | MOV r,r/m | MOVZX | LEA | CMP | TEST | XOR | ADD/OR/ADC/SBB/AND/SUB/XOR r/m,reg */
    if (b == 0x88 || b == 0x89 || b == 0x8A || b == 0x8B || b == 0x8D ||
        b == 0x38 || b == 0x39 || b == 0x3A || b == 0x3B ||
        b == 0x85 || b == 0x84 || b == 0x86 || b == 0x87 ||
        b == 0x33 || b == 0x01 || b == 0x02 || b == 0x03 ||
        b == 0x08 || b == 0x09 || b == 0x0A || b == 0x0B ||
        b == 0x11 || b == 0x12 || b == 0x13 ||
        b == 0x19 || b == 0x1A || b == 0x1B ||
        b == 0x21 || b == 0x22 || b == 0x23 ||
        b == 0x29 || b == 0x2A || b == 0x2B ||
        b == 0x31 || b == 0x32)
        return o + 1 + modrm_off(code, o + 1);

    /* Group 1: ADD/OR/ADC/SBB/AND/SUB/XOR/CMP r/m, imm8/imm32 */
    if (b == 0x80) return o + 1 + modrm_off(code, o + 1) + 1;  /* imm8 */
    if (b == 0x81) return o + 1 + modrm_off(code, o + 1) + 4;  /* imm32 */
    if (b == 0x83) return o + 1 + modrm_off(code, o + 1) + 1;  /* imm8 */

    /* MOV r/m, imm32 */
    if (b == 0xC7) return o + 1 + modrm_off(code, o + 1) + 4;

    /* Group 3 */
    if (b == 0xF6 || b == 0xF7) {
        BYTE mr = code[o + 1];
        int reg = (mr >> 3) & 7;
        if (reg == 0) /* TEST */
            return o + 1 + modrm_off(code, o + 1) + ((b == 0xF6) ? 1 : 4);
        return o + 1 + modrm_off(code, o + 1);
    }

    if (b == 0xE9 || b == 0xE8) return o + 5;   /* JMP/CALL rel32 */
    if (b == 0xEB)              return o + 2;   /* JMP rel8 */
    if (b >= 0x70 && b <= 0x7F) return o + 2;   /* Jcc rel8 */
    if (b >= 0x50 && b <= 0x5F) return o + 1;   /* PUSH/POP */
    if (b == 0xC3 || b == 0xCB || b == 0xC9 || b == 0xCC || b == 0x90)
        return o + 1;
    return 0;
}
#else
static int inst_len(BYTE *code)
{
    BYTE b = code[0];
    if (b == 0x55 || b == 0x53 || b == 0x56 || b == 0x57) return 1;
    if (b >= 0x50 && b <= 0x5F) return 1;
    if (b == 0x6A) return 2;
    if (b == 0x68) return 5;

    if (b == 0x88 || b == 0x89 || b == 0x8A || b == 0x8B || b == 0x8D ||
        b == 0x38 || b == 0x39 || b == 0x3A || b == 0x3B ||
        b == 0x85 || b == 0x84 || b == 0x86 || b == 0x87 ||
        b == 0x33 || b == 0x01 || b == 0x02 || b == 0x03 ||
        b == 0x08 || b == 0x09 || b == 0x0A || b == 0x0B ||
        b == 0x11 || b == 0x12 || b == 0x13 ||
        b == 0x19 || b == 0x1A || b == 0x1B ||
        b == 0x21 || b == 0x22 || b == 0x23 ||
        b == 0x29 || b == 0x2A || b == 0x2B ||
        b == 0x31 || b == 0x32)
        return 1 + modrm_off(code, 1);

    if (b == 0x80 || b == 0x82) return 1 + modrm_off(code, 1) + 1;
    if (b == 0x81) return 1 + modrm_off(code, 1) + 4;
    if (b == 0x83) return 1 + modrm_off(code, 1) + 1;

    if (b == 0xC7) return 1 + modrm_off(code, 1) + 4;

    if (b == 0xF6 || b == 0xF7) {
        BYTE mr = code[1];
        int reg = (mr >> 3) & 7;
        if (reg == 0)
            return 1 + modrm_off(code, 1) + ((b == 0xF6) ? 1 : 4);
        return 1 + modrm_off(code, 1);
    }

    if (b == 0x0F) {
        BYTE op2 = code[1];
        if ((op2 & 0xF0) == 0x80) return 6;
        if (op2 == 0x1F) {
            BYTE mr = code[2];
            int mod = (mr >> 6) & 3;
            if (mod == 0) return 3;
            if (mod == 1) return 4;
            if (mod == 2) return 7;
            return 2;
        }
        if (op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF)
            return 2 + modrm_off(code, 2);
        if ((op2 & 0xF0) == 0x40)
            return 2 + modrm_off(code, 2);
        if (op2 == 0xAF)
            return 2 + modrm_off(code, 2);
        return 2;
    }

    if (b == 0xE9 || b == 0xE8) return 5;
    if (b == 0xEB)              return 2;
    if (b >= 0x70 && b <= 0x7F) return 2;
    if (b == 0xC3 || b == 0xC9 || b == 0x90 || b == 0xCC) return 1;
    if (b == 0xA1 || b == 0xA2 || b == 0xA3) return 5;
    if (b >= 0xB0 && b <= 0xB7) return 2;
    if (b >= 0xB8 && b <= 0xBF) return 5;
    return 1;
}
#endif

static int socks5_handshake(SOCKET s, const struct sockaddr *target, int namelen)
{
    (void)namelen;
    unsigned char buf[22];
    unsigned char greet[] = {5, 1, 0};
    if (send(s, (const char *)greet, sizeof(greet), 0) != sizeof(greet))
        return -1;
    int r = recv(s, (char *)buf, 2, 0);
    if (r != 2 || buf[0] != 5 || buf[1] != 0)
        return -1;
    unsigned char req[22];
    int req_len;
    req[0] = 5; req[1] = 1; req[2] = 0;
    if (target->sa_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)target;
        req[3] = 1;
        memcpy(req + 4, &in->sin_addr, 4);
        memcpy(req + 8, &in->sin_port, 2);
        req_len = 10;
    } else if (target->sa_family == AF_INET6) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)target;
        req[3] = 4;
        memcpy(req + 4, &in6->sin6_addr, 16);
        memcpy(req + 20, &in6->sin6_port, 2);
        req_len = 22;
    } else return -1;
    if (send(s, (const char *)req, req_len, 0) != req_len)
        return -1;
    r = recv(s, (char *)buf, sizeof(buf), 0);
    if (r < 10 || buf[0] != 5 || buf[1] != 0)
        return -1;
    return 0;
}

static int ensure_proxy_resolved(void)
{
    if (g_proxy_ready) return 0;
    memset(&g_proxy_addr, 0, sizeof(g_proxy_addr));
    g_proxy_addr.sin_family = AF_INET;
    g_proxy_addr.sin_port = htons(g_cfg.port);
    g_proxy_addr.sin_addr.s_addr = inet_addr(g_cfg.host);
    if (g_proxy_addr.sin_addr.s_addr == INADDR_NONE) {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return -1;
        struct hostent *he = gethostbyname(g_cfg.host);
        if (!he) return -1;
        memcpy(&g_proxy_addr.sin_addr, he->h_addr_list[0], he->h_length);
    }
    g_proxy_ready = 1;
    return 0;
}

static int should_bypass(const struct sockaddr *name)
{
    if (name->sa_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)name;
        return in->sin_addr.s_addr == g_proxy_addr.sin_addr.s_addr &&
               in->sin_port == g_proxy_addr.sin_port;
    }
    return 0;
}

static int do_proxy_connect(SOCKET s, const struct sockaddr *name, int namelen)
{
    if (ensure_proxy_resolved() != 0) return -1;
    if (should_bypass(name))
        return g_orig_connect(s, name, namelen);
    int r = g_orig_connect(s, (const struct sockaddr *)&g_proxy_addr, sizeof(g_proxy_addr));
    if (r != 0) return r;
    if (socks5_handshake(s, name, namelen) != 0) { closesocket(s); return -1; }
    return 0;
}

static int WINAPI hooked_connect(SOCKET s, const struct sockaddr *name, int namelen)
{
    if (!g_orig_connect) return -1;
    return do_proxy_connect(s, name, namelen);
}

static int WINAPI hooked_wsaconnect(SOCKET s, const struct sockaddr *name, int namelen,
    LPWSABUF cb, LPWSABUF db, LPQOS sq, LPQOS gq)
{
    if (!g_orig_connect) return -1;
    if (do_proxy_connect(s, name, namelen) != 0)
        return g_orig_wsaconnect(s, name, namelen, cb, db, sq, gq);
    return 0;
}

static void inject_into_process(HANDLE hp)
{
    wchar_t path[MAX_PATH];
    DWORD n = GetModuleFileNameW(g_dll, path, MAX_PATH);
    if (!n || n >= MAX_PATH) return;

    size_t sz = (n + 1) * sizeof(wchar_t);
    void *rem = VirtualAllocEx(hp, NULL, sz, MEM_COMMIT, PAGE_READWRITE);
    if (!rem) return;
    WriteProcessMemory(hp, rem, path, sz, NULL);

    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC fp = GetProcAddress(k32, "LoadLibraryW");
    LPTHREAD_START_ROUTINE lib;
    memcpy(&lib, &fp, sizeof(lib));

    HANDLE rt = CreateRemoteThread(hp, NULL, 0, lib, rem, 0, NULL);
    if (rt) { WaitForSingleObject(rt, 2000); CloseHandle(rt); }
    VirtualFreeEx(hp, rem, 0, MEM_RELEASE);
}

static BOOL WINAPI hooked_createprocessw(
    LPCWSTR a, LPWSTR c,
    LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta,
    BOOL ih, DWORD f, LPVOID e, LPCWSTR d,
    LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi)
{
    if (InterlockedExchange(&g_in_create, 1))
        return g_orig_cpw(a, c, pa, ta, ih, f, e, d, si, pi);

    if (f & (DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS)) {
        InterlockedExchange(&g_in_create, 0);
        return g_orig_cpw(a, c, pa, ta, ih, f, e, d, si, pi);
    }

    BOOL susp = (f & CREATE_SUSPENDED) != 0;
    BOOL r = g_orig_cpw(a, c, pa, ta, ih, f | CREATE_SUSPENDED, e, d, si, pi);
    if (r) {
        inject_into_process(pi->hProcess);
        if (!susp) ResumeThread(pi->hThread);
    }
    InterlockedExchange(&g_in_create, 0);
    return r;
}

static BOOL WINAPI hooked_createprocessa(
    LPCSTR a, LPSTR c,
    LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta,
    BOOL ih, DWORD f, LPVOID e, LPCSTR d,
    LPSTARTUPINFOA si, LPPROCESS_INFORMATION pi)
{
    if (InterlockedExchange(&g_in_create, 1))
        return g_orig_cpa(a, c, pa, ta, ih, f, e, d, si, pi);

    if (f & (DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS)) {
        InterlockedExchange(&g_in_create, 0);
        return g_orig_cpa(a, c, pa, ta, ih, f, e, d, si, pi);
    }

    BOOL susp = (f & CREATE_SUSPENDED) != 0;
    BOOL r = g_orig_cpa(a, c, pa, ta, ih, f | CREATE_SUSPENDED, e, d, si, pi);
    if (r) {
        inject_into_process(pi->hProcess);
        if (!susp) ResumeThread(pi->hThread);
    }
    InterlockedExchange(&g_in_create, 0);
    return r;
}

static int do_trampoline(void *func, void *hook, BYTE *saved, int *sn, void **out)
{
    int pos = 0;
    while (pos < JMP_SIZE) {
        int l = inst_len((BYTE *)func + pos);
        if (l <= 0) break;
        pos += l;
    }
    if (pos < JMP_SIZE) pos = JMP_SIZE;

    void *t = VirtualAlloc(NULL, pos + JMP_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!t) return -1;

    memcpy(saved, func, pos);
    memcpy(t, func, pos);
    BYTE *tj = (BYTE *)t + pos;
    tj[0] = 0xE9;
    *(DWORD *)(tj + 1) = (DWORD)((BYTE *)func + pos - ((BYTE *)tj + 5));

    DWORD old;
    VirtualProtect(func, JMP_SIZE, PAGE_EXECUTE_READWRITE, &old);
    BYTE *tg = (BYTE *)func;
    tg[0] = 0xE9;
    *(DWORD *)(tg + 1) = (DWORD)((BYTE *)hook - (tg + 5));
    VirtualProtect(func, JMP_SIZE, old, &old);
    FlushInstructionCache(GetCurrentProcess(), func, JMP_SIZE);

    *sn = pos;
    *out = t;
    return 0;
}

static void install_hooks(void)
{
    HMODULE mod = GetModuleHandleA("ws2_32.dll");
    if (!mod) {
        mod = LoadLibraryA("ws2_32.dll");
        if (!mod) return;
    }

    void *addr;
    addr = GetProcAddress(mod, "connect");
    if (addr) {
        g_target_connect = addr;
        do_trampoline(addr, hooked_connect, g_saved_conn, &g_saved_conn_n, (void **)&g_orig_connect);
    }
    addr = GetProcAddress(mod, "WSAConnect");
    if (addr) {
        g_target_wsaconnect = addr;
        do_trampoline(addr, hooked_wsaconnect, g_saved_wsa, &g_saved_wsa_n, (void **)&g_orig_wsaconnect);
    }

    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    addr = GetProcAddress(k32, "CreateProcessW");
    if (addr)
        do_trampoline(addr, hooked_createprocessw, g_saved_cpw, &g_saved_cpw_n, (void **)&g_orig_cpw);
    addr = GetProcAddress(k32, "CreateProcessA");
    if (addr)
        do_trampoline(addr, hooked_createprocessa, g_saved_cpa, &g_saved_cpa_n, (void **)&g_orig_cpa);
}

BOOL WINAPI DllMain(HINSTANCE dll, DWORD reason, LPVOID res)
{
    (void)res;
    if (reason == DLL_PROCESS_ATTACH) {
        g_dll = dll;
        DisableThreadLibraryCalls(dll);
        char buf[512];
        DWORD len = GetEnvironmentVariableA(ENV_VAR, buf, sizeof(buf));
        if (len > 0 && len < sizeof(buf)) {
            char *c = strchr(buf, ':');
            if (c) {
                *c++ = 0;
                strncpy(g_cfg.host, buf, sizeof(g_cfg.host) - 1);
                g_cfg.host[sizeof(g_cfg.host) - 1] = 0;
                g_cfg.port = (unsigned short)atoi(c);
                install_hooks();
            }
        }
    }
    return TRUE;
}
