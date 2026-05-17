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
        /* SETcc (0x90-0x9F), CMPXCHG (0xB0-0xB1), XADD (0xC0-0xC1) and
           all other ModRM-based 2-byte opcodes for safety */
        if ((op2 & 0xF0) == 0x90 ||  /* SETcc */
            (op2 & 0xFC) == 0xB0 ||  /* CMPXCHG */
            (op2 & 0xFE) == 0xC0 ||  /* XADD */
            op2 == 0xA3 || op2 == 0xAB || op2 == 0xB3 || op2 == 0xBB ||
            op2 == 0xA4 || op2 == 0xAC ||  /* SHLD / SHRD (ModRM + imm8) */
            op2 == 0x02 || op2 == 0x03)    /* LAR / LSL */
            return o + 2 + modrm_off(code, o + 2);
        if (op2 == 0xA4 || op2 == 0xAC || op2 == 0xC4 || op2 == 0xC5)
            return o + 2 + modrm_off(code, o + 2) + 1;  /* +imm8 */
        return 0;
    }

    /* ADD/OR/ADC/SBB/AND/SUB/XOR/CMP r/m8/r, r8/r (all 16 variants) */
    if (b <= 0x03 ||
        (b >= 0x08 && b <= 0x0B) ||
        (b >= 0x10 && b <= 0x13) ||
        (b >= 0x18 && b <= 0x1B) ||
        (b >= 0x20 && b <= 0x23) ||
        (b >= 0x28 && b <= 0x2B) ||
        (b >= 0x30 && b <= 0x33) ||
        (b >= 0x38 && b <= 0x3B) ||
        b == 0x63 ||       /* MOVSXD (x64) */
        b == 0x84 || b == 0x85 ||  /* TEST */
        b == 0x86 || b == 0x87 ||  /* XCHG */
        b == 0x88 || b == 0x89 ||  /* MOV r/m, r */
        b == 0x8A || b == 0x8B ||  /* MOV r, r/m */
        b == 0x8C || b == 0x8D || b == 0x8E)  /* MOV Sreg / LEA / MOV Sreg */
        return o + 1 + modrm_off(code, o + 1);

    /* Group 1: ADD/OR/ADC/SBB/AND/SUB/XOR/CMP r/m, imm8/imm32 */
    if (b == 0x80) return o + 1 + modrm_off(code, o + 1) + 1;  /* imm8 */
    if (b == 0x81) return o + 1 + modrm_off(code, o + 1) + 4;  /* imm32 */
    if (b == 0x83) return o + 1 + modrm_off(code, o + 1) + 1;  /* imm8 */

    /* IMUL r, r/m, imm */
    if (b == 0x69) return o + 1 + modrm_off(code, o + 1) + 4;  /* imm32 */
    if (b == 0x6B) return o + 1 + modrm_off(code, o + 1) + 1;  /* imm8 */

    /* Group 2: SHL/SHR/SAR/ROL/ROR/RCL/RCR */
    if (b == 0xC0) return o + 1 + modrm_off(code, o + 1) + 1;  /* r/m8, imm8 */
    if (b == 0xC1) return o + 1 + modrm_off(code, o + 1) + 1;  /* r/m32/64, imm8 */
    if (b == 0xD0) return o + 1 + modrm_off(code, o + 1);      /* r/m8, 1 */
    if (b == 0xD1) return o + 1 + modrm_off(code, o + 1);      /* r/m32/64, 1 */
    if (b == 0xD2) return o + 1 + modrm_off(code, o + 1);      /* r/m8, CL */
    if (b == 0xD3) return o + 1 + modrm_off(code, o + 1);      /* r/m32/64, CL */

    /* MOV r/m, imm32 */
    if (b == 0xC7) return o + 1 + modrm_off(code, o + 1) + 4;
    /* MOV r/m8, imm8 */
    if (b == 0xC6) return o + 1 + modrm_off(code, o + 1) + 1;

    /* Group 4: INC/DEC r/m8 */
    if (b == 0xFE) return o + 1 + modrm_off(code, o + 1);

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
    if (b == 0x6A) return o + 2;                /* PUSH imm8 */
    if (b == 0x68) return o + 5;                /* PUSH imm32 */
    if (b == 0xFF || b == 0x8F)                 /* INC/DEC/CALL/JMP/PUSH/POP r/m */
        return o + 1 + modrm_off(code, o + 1);
    if (b == 0xC3 || b == 0xCB || b == 0xC9 || b == 0xCC || b == 0x90)
        return o + 1;
    if (b == 0xC2 || b == 0xCA) return o + 3;  /* RET imm16 */
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
        b == 0x31 || b == 0x32 ||
        b <= 0x03 ||
        (b >= 0x10 && b <= 0x13) ||
        (b >= 0x18 && b <= 0x1B) ||
        (b >= 0x20 && b <= 0x23) ||
        (b >= 0x28 && b <= 0x2B) ||
        (b >= 0x30 && b <= 0x33) ||
        b == 0x8C || b == 0x8E)
        return 1 + modrm_off(code, 1);

    if (b == 0x80 || b == 0x82) return 1 + modrm_off(code, 1) + 1;
    if (b == 0x81) return 1 + modrm_off(code, 1) + 4;
    if (b == 0x83) return 1 + modrm_off(code, 1) + 1;

    if (b == 0x69) return 1 + modrm_off(code, 1) + 4;
    if (b == 0x6B) return 1 + modrm_off(code, 1) + 1;

    if (b == 0xC0) return 1 + modrm_off(code, 1) + 1;
    if (b == 0xC1) return 1 + modrm_off(code, 1) + 1;
    if (b == 0xD0) return 1 + modrm_off(code, 1);
    if (b == 0xD1) return 1 + modrm_off(code, 1);
    if (b == 0xD2) return 1 + modrm_off(code, 1);
    if (b == 0xD3) return 1 + modrm_off(code, 1);

    if (b == 0xC7) return 1 + modrm_off(code, 1) + 4;
    if (b == 0xC6) return 1 + modrm_off(code, 1) + 1;

    if (b == 0xFE) return 1 + modrm_off(code, 1);

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
    if (b == 0xFF || b == 0x8F) return 1 + modrm_off(code, 1);
    if (b == 0xC3 || b == 0xC9 || b == 0x90 || b == 0xCC) return 1;
    if (b == 0xC2 || b == 0xCA) return 3;
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
        if (in->sin_addr.s_addr == g_proxy_addr.sin_addr.s_addr &&
            in->sin_port == g_proxy_addr.sin_port)
            return 1;
        unsigned long a = ntohl(in->sin_addr.s_addr);
        if ((a >> 24) == 127) return 1;
        if (ntohs(in->sin_port) == 53) return 1;
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

// Find RIP-relative disp32 offset within an instruction, or -1.
// Works for all x64 one-byte and two-byte (0F xx) opcodes.
// Uses blacklist approach: only known non-ModRM opcodes return -1.
static int rip_disp_off(BYTE *code)
{
    int o = 0;
    while (code[o] >= 0x40 && code[o] <= 0x4F) o++;
    while (code[o] == 0xF0 || code[o] == 0xF2 || code[o] == 0xF3 ||
           code[o] == 0x66 || code[o] == 0x67 ||
           code[o] == 0x2E || code[o] == 0x3E || code[o] == 0x26 ||
           code[o] == 0x64 || code[o] == 0x65)
        o++;
    BYTE b = code[o];

    if (b == 0x0F) {
        BYTE op2 = code[o + 1];
        if ((op2 >= 0x80 && op2 <= 0x8F) ||
            op2 == 0x05 || op2 == 0x07 ||
            op2 == 0xA0 || op2 == 0xA1 ||
            op2 == 0xA8 || op2 == 0xA9 ||
            op2 == 0x30 || op2 == 0x31 ||
            op2 == 0x32 || op2 == 0x33 ||
            op2 == 0x34 || op2 == 0x35 ||
            op2 == 0x37)
            return -1;
        int mo = o + 2;
        BYTE mr = code[mo];
        int mod = (mr >> 6) & 3;
        int rm  = mr & 7;
        if (mod == 0 && rm == 5)           return mo + 1;
        if (mod != 3 && rm == 4) {
            if (mod == 0 && (code[mo + 1] & 7) == 5) return mo + 2;
        }
        return -1;
    }

    /* 1-byte opcodes that DON'T use ModRM */
    if ((b >= 0x50 && b <= 0x5F) ||  /* PUSH/POP reg */
        (b >= 0x70 && b <= 0x7F) ||  /* Jcc rel8 */
        (b >= 0xE0 && b <= 0xE3) ||  /* LOOP/JECXZ */
        (b >= 0xB0 && b <= 0xBF) ||  /* MOV r, imm8/32 */
        (b >= 0xA0 && b <= 0xA3) ||  /* MOV moffs */
        (b >= 0xA8 && b <= 0xAD) ||  /* TEST/STOS/LODS/SCAS/CMPS */
        (b >= 0x04 && b <= 0x05) ||
        (b >= 0x0C && b <= 0x0D) ||
        (b >= 0x14 && b <= 0x15) ||
        (b >= 0x1C && b <= 0x1D) ||
        (b >= 0x24 && b <= 0x25) ||
        (b >= 0x2C && b <= 0x2D) ||
        (b >= 0x34 && b <= 0x35) ||
        (b >= 0x3C && b <= 0x3D) ||
        b == 0xE8 || b == 0xE9 || b == 0xEB ||
        b == 0x6A || b == 0x68 ||
        b == 0x06 || b == 0x07 ||
        b == 0x0E || b == 0x0F ||
        b == 0x16 || b == 0x17 ||
        b == 0x1E || b == 0x1F ||
        b == 0x27 || b == 0x2F ||
        b == 0x37 || b == 0x3F ||
        b == 0x60 || b == 0x61 || b == 0x62 ||
        b == 0x6C || b == 0x6D || b == 0x6E || b == 0x6F ||
        b == 0xC3 || b == 0xCB || b == 0xC9 || b == 0xCC || b == 0x90 ||
        b == 0x9C || b == 0x9D ||
        b == 0xC2 || b == 0xCA ||
        b == 0xE4 || b == 0xE5 || b == 0xE6 || b == 0xE7 ||
        b == 0xEC || b == 0xED || b == 0xEE || b == 0xEF ||
        b == 0xF4 || b == 0xF5 ||
        b == 0xF8 || b == 0xF9 || b == 0xFA || b == 0xFB ||
        b == 0xFC || b == 0xFD) {
        return -1;
    }

    /* Has ModRM at offset o+1 */
    int mo = o + 1;
    BYTE mr = code[mo];
    int mod = (mr >> 6) & 3;
    int rm  = mr & 7;
    if (mod == 0 && rm == 5)           return mo + 1;
    if (mod != 3 && rm == 4) {
        BYTE sib = code[mo + 1];
        if (mod == 0 && (sib & 7) == 5) return mo + 2;
    }
    return -1;
}

/* Allocate executable memory within NEAR_MAX bytes of target.
   Uses VirtualQuery to find free pages (same approach as MinHook). */
#define NEAR_MAX 0x20000000  /* 512 MB in each direction = 1GB total span */

static void *alloc_near(void *target, size_t size)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    DWORD gran = si.dwAllocationGranularity;  /* typically 64 KB */
    ULONG_PTR low  = (ULONG_PTR)si.lpMinimumApplicationAddress;
    ULONG_PTR high = (ULONG_PTR)si.lpMaximumApplicationAddress;
    ULONG_PTR t = (ULONG_PTR)target;

    ULONG_PTR minAddr = (t > NEAR_MAX) ? (t - NEAR_MAX) : low;
    ULONG_PTR maxAddr = (t + NEAR_MAX < high) ? (t + NEAR_MAX) : high;

    /* Adjust for size */
    if (maxAddr > size) maxAddr -= size; else maxAddr = low;
    if (maxAddr < minAddr) return NULL;

    /* Search backward from target */
    {
        ULONG_PTR tryAddr = t;
        tryAddr -= tryAddr % gran;
        while (tryAddr >= minAddr) {
            MEMORY_BASIC_INFORMATION mbi;
            if (!VirtualQuery((void *)tryAddr, &mbi, sizeof(mbi)))
                break;
            if (mbi.State == MEM_FREE && mbi.RegionSize >= size) {
                void *p = VirtualAlloc((void *)tryAddr, size,
                    MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                if (p) return p;
            }
            tryAddr = (ULONG_PTR)mbi.AllocationBase;
            if (tryAddr < gran) break;
            tryAddr -= gran;
        }
    }

    /* Search forward from target */
    {
        ULONG_PTR tryAddr = t - (t % gran) + gran;
        while (tryAddr <= maxAddr) {
            MEMORY_BASIC_INFORMATION mbi;
            if (!VirtualQuery((void *)tryAddr, &mbi, sizeof(mbi)))
                break;
            if (mbi.State == MEM_FREE && mbi.RegionSize >= size) {
                void *p = VirtualAlloc((void *)tryAddr, size,
                    MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                if (p) return p;
            }
            tryAddr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
            tryAddr = (tryAddr + gran - 1) / gran * gran;
        }
    }

    return NULL;
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

    /* Allocate the trampoline NEAR the target so that 32-bit relative
       jumps and RIP-relative displacement adjustments work correctly. */
    void *t = alloc_near(func, pos + JMP_SIZE);
    if (!t) return -1;

    memcpy(saved, func, pos);
    memcpy(t, func, pos);

    /* Fix RIP-relative displacements in the trampoline copy.
       Because alloc_near guarantees t is within NEAR_MAX of func,
       the difference fits in a 32-bit signed int. */
    /* Verify the adjustment fits in 32-bit signed (should always be true
       thanks to alloc_near, but check anyway). */
    intptr_t d64 = (BYTE *)func - (BYTE *)t;
#if defined(_WIN64) || defined(__x86_64__)
    if (d64 > 0x7FFFFFFFLL || d64 < -0x7FFFFFFFLL) {
        VirtualFree(t, 0, MEM_RELEASE);
        return -1;
    }
#endif
    int diff = (int)d64;
    if (diff) {
        int scan = 0;
        while (scan < pos) {
            int r = rip_disp_off((BYTE *)func + scan);
            if (r >= 0) {
                int *d = (int *)((BYTE *)t + scan + r);
                *d += diff;
            }
            int l = inst_len((BYTE *)func + scan);
            if (l <= 0) break;
            scan += l;
        }
    }

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
