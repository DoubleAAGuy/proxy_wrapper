#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>



#define ENV_VAR "PROXY_WRAPPER_PROXY"

#ifdef _WIN64
#define JMP_SIZE 14
#else
#define JMP_SIZE 5
#endif

typedef int (WINAPI *connect_t)(SOCKET, const struct sockaddr *, int);

typedef struct {
    char host[256];
    unsigned short port;
} proxy_cfg_t;

static proxy_cfg_t g_cfg;
static int g_cfg_ok = 0;
static connect_t g_original = NULL;
static BYTE g_saved[JMP_SIZE];
static void *g_target = NULL;

static int socks5_handshake(SOCKET s, const struct sockaddr *target, int namelen)
{
    (void)namelen;
    unsigned char buf[22];
    int r;

    unsigned char greet[] = {5, 1, 0};
    if (send(s, (const char *)greet, sizeof(greet), 0) != sizeof(greet))
        return -1;

    r = recv(s, (char *)buf, 2, 0);
    if (r != 2 || buf[0] != 5 || buf[1] != 0)
        return -1;

    unsigned char req[22];
    int req_len;
    req[0] = 5;
    req[1] = 1;
    req[2] = 0;

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

static int WINAPI hooked_connect(SOCKET s, const struct sockaddr *name, int namelen)
{
    struct sockaddr_in proxy_addr;
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(g_cfg.port);

    struct hostent *he = gethostbyname(g_cfg.host);
    if (!he)
        return g_original(s, name, namelen);
    memcpy(&proxy_addr.sin_addr, he->h_addr_list[0], he->h_length);

    if (name->sa_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)name;
        if (in->sin_addr.s_addr == proxy_addr.sin_addr.s_addr &&
            in->sin_port == proxy_addr.sin_port)
            return g_original(s, name, namelen);
    }

    int r = g_original(s, (const struct sockaddr *)&proxy_addr, sizeof(proxy_addr));
    if (r != 0)
        return r;

    if (socks5_handshake(s, name, namelen) != 0) {
        closesocket(s);
        return -1;
    }

    return 0;
}

static void install_hook(void)
{
    HMODULE mod = GetModuleHandleA("ws2_32.dll");
    if (!mod) return;

    g_target = GetProcAddress(mod, "connect");
    if (!g_target) return;

    void *trampoline = VirtualAlloc(NULL, JMP_SIZE * 2, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!trampoline) return;

    DWORD old;
    if (!VirtualProtect(g_target, JMP_SIZE, PAGE_EXECUTE_READWRITE, &old)) return;

    memcpy(g_saved, g_target, JMP_SIZE);
    memcpy(trampoline, g_target, JMP_SIZE);

#ifdef _WIN64
    BYTE *tjmp = (BYTE *)trampoline + JMP_SIZE;
    tjmp[0] = 0xFF; tjmp[1] = 0x25;
    *(DWORD *)(tjmp + 2) = 0;
    *(ULONG_PTR *)(tjmp + 6) = (ULONG_PTR)((BYTE *)g_target + JMP_SIZE);

    BYTE *tgt = (BYTE *)g_target;
    tgt[0] = 0xFF; tgt[1] = 0x25;
    *(DWORD *)(tgt + 2) = 0;
    *(ULONG_PTR *)(tgt + 6) = (ULONG_PTR)hooked_connect;
#else
    BYTE *tjmp = (BYTE *)trampoline + JMP_SIZE;
    tjmp[0] = 0xE9;
    *(DWORD *)(tjmp + 1) = (DWORD)((BYTE *)g_target + JMP_SIZE - (tjmp + 5));

    BYTE *tgt = (BYTE *)g_target;
    tgt[0] = 0xE9;
    *(DWORD *)(tgt + 1) = (DWORD)((BYTE *)hooked_connect - (tgt + 5));
#endif

    VirtualProtect(g_target, JMP_SIZE, old, &old);
    FlushInstructionCache(GetCurrentProcess(), g_target, JMP_SIZE);

    g_original = (connect_t)trampoline;
}

BOOL WINAPI DllMain(HINSTANCE dll, DWORD reason, LPVOID res)
{
    (void)res;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(dll);
        char buf[512];
        DWORD len = GetEnvironmentVariableA(ENV_VAR, buf, sizeof(buf));
        if (len > 0 && len < sizeof(buf)) {
            char *colon = strchr(buf, ':');
            if (colon) {
                *colon++ = 0;
                strncpy(g_cfg.host, buf, sizeof(g_cfg.host) - 1);
                g_cfg.host[sizeof(g_cfg.host) - 1] = 0;
                g_cfg.port = (unsigned short)atoi(colon);
                g_cfg_ok = 1;
                install_hook();
            }
        }
    }
    return TRUE;
}
