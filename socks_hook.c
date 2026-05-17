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

typedef struct {
    char host[256];
    unsigned short port;
} proxy_cfg_t;

static proxy_cfg_t g_cfg;

static struct {
    connect_t trampoline;
    void *target;
    BYTE saved[16];
    int save_size;
} g_connect;

static struct {
    wsaconnect_t trampoline;
    void *target;
    BYTE saved[16];
    int save_size;
} g_wsaconnect;

static struct sockaddr_in g_proxy_addr;
static int g_proxy_resolved = 0;

#ifdef _WIN64
static int inst_len(BYTE *code)
{
    int o = 0;
    if (code[o] >= 0x40 && code[o] <= 0x4F) o++;
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
        if (op2 == 0xB6 || op2 == 0xB7) return o + 3;
        if (op2 == 0xAF) return o + 3;
        return 0;
    }
    if (b == 0x83) {
        BYTE mr = code[o + 1];
        int mod = (mr >> 6) & 3;
        int len = o + 3;
        if (mod == 1) len++;
        else if (mod == 2) len += 4;
        else if (mod == 0 && (mr & 7) == 4) len++;
        else if (mod == 0 && (mr & 7) == 5) len += 4;
        if ((mr & 7) == 4) {
            BYTE sib = code[len - 1];
            if ((sib & 7) == 5 && mod == 0) len += 4;
        }
        return len;
    }
    if (b == 0x89 || b == 0x8B || b == 0x8D) {
        BYTE mr = code[o + 1];
        int mod = (mr >> 6) & 3;
        int rm = mr & 7;
        int len = o + 2;
        if (mod == 1) len++;
        else if (mod == 2) len += 4;
        else if (mod == 0 && rm == 5) len += 4;
        if (rm == 4) {
            BYTE sib = code[len];
            len++;
            BYTE index = (sib >> 3) & 7;
            (void)(sib & 7);
            if (index == 5 && mod == 0) len += 4;
            if (mod == 1) len++;
            else if (mod == 2) len += 4;
        }
        return len;
    }
    if ((b >= 0x50 && b <= 0x57) || b == 0x55) return o + 1;
    if (b == 0x85 || b == 0x8A) {
        BYTE mr = code[o + 1];
        int mod = (mr >> 6) & 3;
        int len = o + 2;
        if (mod == 1) len++;
        else if (mod == 2) len += 4;
        return len;
    }
    if (b == 0x33) {
        BYTE mr = code[o + 1];
        int mod = (mr >> 6) & 3;
        int len = o + 2;
        if (mod == 1) len++;
        else if (mod == 2) len += 4;
        return len;
    }
    if (b == 0x48 || b == 0x8B || b == 0x8D || b == 0x39 || b == 0x3B)
        return o + 2;
    if (b == 0xE9) return o + 5;
    if (b == 0xEB) return o + 2;
    if (b == 0xC3 || b == 0xCB || b == 0xC9 || b == 0xCC || b == 0x90)
        return o + 1;
    if (b == 0xF6) {
        BYTE mr = code[o + 1];
        int mod = (mr >> 6) & 3;
        int len = o + 2;
        if ((mr & 0x38) == 0) len++;
        if (mod == 1) len++;
        else if (mod == 2) len += 4;
        return len;
    }
    if (b == 0xC7) {
        BYTE mr = code[o + 1];
        int mod = (mr >> 6) & 3;
        int len = o + 6;
        if (mod == 1) len++;
        else if (mod == 2) len += 4;
        return len;
    }
    if (b == 0x8A || b == 0x8B) return o + 2;
    if (b == 0x80 || b == 0x81) {
        BYTE mr = code[o + 1];
        int mod = (mr >> 6) & 3;
        int len = (b == 0x80) ? o + 3 : o + 6;
        if (mod == 1) len++;
        else if (mod == 2) len += 4;
        return len;
    }
    return 0;
}
#else
static int inst_len(BYTE *code)
{
    BYTE b = code[0];
    if (b == 0x55 || b == 0x53 || b == 0x56 || b == 0x57) return 1;
    if (b == 0x6A) return 2;
    if (b == 0x68) return 5;
    if (b == 0x8B) {
        BYTE mr = code[1];
        int mod = (mr >> 6) & 3;
        int len = 2;
        if (mod == 1) len++;
        else if (mod == 2) len += 4;
        if ((mr & 7) == 4 && mod != 3) len++;
        return len;
    }
    if (b == 0x83) {
        BYTE mr = code[1];
        int mod = (mr >> 6) & 3;
        int len = 3;
        if (mod == 1) len++;
        else if (mod == 2) len += 4;
        return len;
    }
    if (b == 0x81 || b == 0xC7) {
        BYTE mr = code[1];
        int mod = (mr >> 6) & 3;
        int len = 6;
        if (mod == 1) len++;
        else if (mod == 2) len += 4;
        return len;
    }
    if (b == 0x8D) {
        BYTE mr = code[1];
        int mod = (mr >> 6) & 3;
        int len = 2;
        if (mod == 1) len++;
        else if (mod == 2) len += 4;
        if ((mr & 7) == 4) len++;
        return len;
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
            return 3;
        return 2;
    }
    if ((b & 0xFC) == 0x80) return 3;
    if (b == 0xE9) return 5;
    if (b == 0xEB) return 2;
    if (b == 0xC3 || b == 0xC9 || b == 0x90 || b == 0xCC) return 1;
    if (b == 0xA1) return 5;
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
    } else {
        return -1;
    }

    if (send(s, (const char *)req, req_len, 0) != req_len)
        return -1;

    r = recv(s, (char *)buf, sizeof(buf), 0);
    if (r < 10 || buf[0] != 5 || buf[1] != 0)
        return -1;

    return 0;
}

static int resolve_proxy(void)
{
    if (g_proxy_resolved) return 0;
    memset(&g_proxy_addr, 0, sizeof(g_proxy_addr));
    g_proxy_addr.sin_family = AF_INET;
    g_proxy_addr.sin_port = htons(g_cfg.port);
    struct hostent *he = gethostbyname(g_cfg.host);
    if (!he) return -1;
    memcpy(&g_proxy_addr.sin_addr, he->h_addr_list[0], he->h_length);
    g_proxy_resolved = 1;
    return 0;
}

static int should_bypass(const struct sockaddr *name)
{
    if (name->sa_family == AF_INET || name->sa_family == AF_INET6) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)name;
        if (in->sin_addr.s_addr == g_proxy_addr.sin_addr.s_addr &&
            in->sin_port == g_proxy_addr.sin_port)
            return 1;
    }
    return 0;
}

static int do_proxy_connect(SOCKET s, const struct sockaddr *name, int namelen)
{
    if (resolve_proxy() != 0)
        return -1;

    if (should_bypass(name))
        return g_connect.trampoline(s, name, namelen);

    int r = g_connect.trampoline(s, (const struct sockaddr *)&g_proxy_addr, sizeof(g_proxy_addr));
    if (r != 0) return r;

    if (socks5_handshake(s, name, namelen) != 0) {
        closesocket(s);
        return -1;
    }
    return 0;
}

static int WINAPI hooked_connect(SOCKET s, const struct sockaddr *name, int namelen)
{
    if (!g_connect.trampoline || !g_proxy_resolved)
        return g_connect.trampoline(s, name, namelen);
    return do_proxy_connect(s, name, namelen);
}

static int WINAPI hooked_wsaconnect(SOCKET s, const struct sockaddr *name, int namelen,
    LPWSABUF cb, LPWSABUF db, LPQOS sq, LPQOS gq)
{
    if (!g_wsaconnect.trampoline || !g_proxy_resolved)
        return g_wsaconnect.trampoline(s, name, namelen, cb, db, sq, gq);

    if (do_proxy_connect(s, name, namelen) != 0)
        return g_wsaconnect.trampoline(s, name, namelen, cb, db, sq, gq);

    return 0;
}

static int prepare_trampoline(void *func, void *hook, BYTE *saved, int *save_size, void **trampoline)
{
    int pos = 0;
    while (pos < JMP_SIZE) {
        int len = inst_len((BYTE *)func + pos);
        if (len <= 0) break;
        pos += len;
    }
    if (pos < JMP_SIZE) pos = JMP_SIZE;

    void *tramp = VirtualAlloc(NULL, pos + JMP_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!tramp) return -1;

    memcpy(saved, func, pos);
    memcpy(tramp, func, pos);

    BYTE *tjmp = (BYTE *)tramp + pos;
    tjmp[0] = 0xE9;
    *(DWORD *)(tjmp + 1) = (DWORD)((BYTE *)func + pos - ((BYTE *)tjmp + 5));

    DWORD old;
    VirtualProtect(func, JMP_SIZE, PAGE_EXECUTE_READWRITE, &old);

    BYTE *tgt = (BYTE *)func;
    tgt[0] = 0xE9;
    *(DWORD *)(tgt + 1) = (DWORD)((BYTE *)hook - (tgt + 5));

    VirtualProtect(func, JMP_SIZE, old, &old);
    FlushInstructionCache(GetCurrentProcess(), func, JMP_SIZE);

    *save_size = pos;
    *trampoline = tramp;
    return 0;
}

static void install_hooks(void)
{
    HMODULE mod = GetModuleHandleA("ws2_32.dll");
    if (!mod) {
        mod = LoadLibraryA("ws2_32.dll");
        if (!mod) return;
    }

    void *addr = GetProcAddress(mod, "connect");
    if (addr) {
        g_connect.target = addr;
        prepare_trampoline(addr, hooked_connect,
            g_connect.saved, &g_connect.save_size,
            (void **)&g_connect.trampoline);
    }

    addr = GetProcAddress(mod, "WSAConnect");
    if (addr) {
        g_wsaconnect.target = addr;
        prepare_trampoline(addr, hooked_wsaconnect,
            g_wsaconnect.saved, &g_wsaconnect.save_size,
            (void **)&g_wsaconnect.trampoline);
    }

    if (g_connect.trampoline)
        resolve_proxy();
}

BOOL WINAPI DllMain(HINSTANCE dll, DWORD reason, LPVOID res)
{
    (void)res;
    if (reason == DLL_PROCESS_ATTACH) {
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
