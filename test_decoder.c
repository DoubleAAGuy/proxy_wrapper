// Instruction decoder test – compiles natively on any platform
// Must be kept in sync with socks_hook.c decoder functions.
#include <stdio.h>
#include <string.h>

typedef unsigned char BYTE;

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

#define JMP_SIZE 5

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
        if ((op2 & 0xF0) == 0x40)
            return o + 2 + modrm_off(code, o + 2);
        if (op2 == 0xAF)
            return o + 2 + modrm_off(code, o + 2);
        if ((op2 & 0xF0) == 0x90 ||
            (op2 & 0xFC) == 0xB0 ||
            (op2 & 0xFE) == 0xC0 ||
            op2 == 0xA3 || op2 == 0xAB || op2 == 0xB3 || op2 == 0xBB ||
            op2 == 0xA4 || op2 == 0xAC ||
            op2 == 0x02 || op2 == 0x03)
            return o + 2 + modrm_off(code, o + 2);
        if (op2 == 0xA4 || op2 == 0xAC || op2 == 0xC4 || op2 == 0xC5)
            return o + 2 + modrm_off(code, o + 2) + 1;
        return 0;
    }

    if (b <= 0x03 ||
        (b >= 0x08 && b <= 0x0B) ||
        (b >= 0x10 && b <= 0x13) ||
        (b >= 0x18 && b <= 0x1B) ||
        (b >= 0x20 && b <= 0x23) ||
        (b >= 0x28 && b <= 0x2B) ||
        (b >= 0x30 && b <= 0x33) ||
        (b >= 0x38 && b <= 0x3B) ||
        b == 0x63 ||
        b == 0x84 || b == 0x85 ||
        b == 0x86 || b == 0x87 ||
        b == 0x88 || b == 0x89 ||
        b == 0x8A || b == 0x8B ||
        b == 0x8C || b == 0x8D || b == 0x8E)
        return o + 1 + modrm_off(code, o + 1);

    if (b == 0x80) return o + 1 + modrm_off(code, o + 1) + 1;
    if (b == 0x81) return o + 1 + modrm_off(code, o + 1) + 4;
    if (b == 0x83) return o + 1 + modrm_off(code, o + 1) + 1;

    if (b == 0x69) return o + 1 + modrm_off(code, o + 1) + 4;
    if (b == 0x6B) return o + 1 + modrm_off(code, o + 1) + 1;

    if (b == 0xC0) return o + 1 + modrm_off(code, o + 1) + 1;
    if (b == 0xC1) return o + 1 + modrm_off(code, o + 1) + 1;
    if (b == 0xD0) return o + 1 + modrm_off(code, o + 1);
    if (b == 0xD1) return o + 1 + modrm_off(code, o + 1);
    if (b == 0xD2) return o + 1 + modrm_off(code, o + 1);
    if (b == 0xD3) return o + 1 + modrm_off(code, o + 1);

    if (b == 0xC7) return o + 1 + modrm_off(code, o + 1) + 4;
    if (b == 0xC6) return o + 1 + modrm_off(code, o + 1) + 1;

    if (b == 0xFE) return o + 1 + modrm_off(code, o + 1);

    if (b == 0xF6 || b == 0xF7) {
        BYTE mr = code[o + 1];
        int reg = (mr >> 3) & 7;
        if (reg == 0)
            return o + 1 + modrm_off(code, o + 1) + ((b == 0xF6) ? 1 : 4);
        return o + 1 + modrm_off(code, o + 1);
    }

    if (b == 0xE9 || b == 0xE8) return o + 5;
    if (b == 0xEB)              return o + 2;
    if (b >= 0x70 && b <= 0x7F) return o + 2;
    if (b >= 0x50 && b <= 0x5F) return o + 1;
    if (b == 0x6A) return o + 2;
    if (b == 0x68) return o + 5;
    if (b == 0xFF || b == 0x8F)
        return o + 1 + modrm_off(code, o + 1);
    if (b == 0xC3 || b == 0xCB || b == 0xC9 || b == 0xCC || b == 0x90)
        return o + 1;
    if (b == 0xC2 || b == 0xCA) return o + 3;
    return 0;
}

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

    if ((b >= 0x50 && b <= 0x5F) ||
        (b >= 0x70 && b <= 0x7F) ||
        (b >= 0xE0 && b <= 0xE3) ||
        (b >= 0xB0 && b <= 0xBF) ||
        (b >= 0xA0 && b <= 0xA3) ||
        (b >= 0xA8 && b <= 0xAD) ||
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

typedef struct {
    const char *name;
    BYTE bytes[16];
    int expected_len;
    int expected_rip;
} testcase;

static testcase tests[] = {
    {"MOV [rsp+8], rbx",      {0x48,0x89,0x5C,0x24,0x08}, 5, -1},
    {"MOV [rsp+10], rsi",     {0x48,0x89,0x74,0x24,0x10}, 5, -1},
    {"PUSH rdi",              {0x57},                     1, -1},
    {"PUSH r14",              {0x41,0x56},                2, -1},
    {"SUB rsp, 30h",          {0x48,0x83,0xEC,0x30},      4, -1},
    {"MOV rbp, rsp",          {0x48,0x8B,0xEC},           3, -1},
    {"JMP rel32",             {0xE9,0x78,0x56,0x34,0x12}, 5, -1},
    {"CALL rel32",            {0xE8,0x78,0x56,0x34,0x12}, 5, -1},
    {"JMP [rip+off]",         {0xFF,0x25,0x78,0x56,0x34,0x12}, 6, 2},
    {"CALL [rip+off]",        {0xFF,0x15,0x78,0x56,0x34,0x12}, 6, 2},
    {"MOV rax, [rip+off]",    {0x48,0x8B,0x05,0x78,0x56,0x34,0x12}, 7, 3},
    {"MOV rax, [rbx+rcx*4]",  {0x48,0x8B,0x04,0x98},      4, -1},
    {"NOP",                   {0x90},                     1, -1},
    {"RET",                   {0xC3},                     1, -1},
    {"RET imm16",             {0xC2,0x08,0x00},           3, -1},
    {"LEAVE",                 {0xC9},                     1, -1},
    {"JMP rel8",              {0xEB,0x10},                2, -1},
    {"JZ rel8",               {0x74,0x05},                2, -1},
    {"PUSH imm8",             {0x6A,0x20},                2, -1},
    {"PUSH imm32",            {0x68,0x78,0x56,0x34,0x12}, 5, -1},
    {"FF25 stub",             {0xFF,0x25,0x00,0x00,0x00,0x00}, 6, 2},

    /* With SIB RIP-relative */
    {"LEA [rip+off] (REX)",  {0x48,0x8D,0x05,0x78,0x56,0x34,0x12}, 7, 3},

    /* ADD r/m8, r8 (0x00) */
    {"ADD [rax], cl",         {0x00,0x08},  2, -1},

    /* ADD [rax+disp32], r (0x01) */
    {"ADD [rip+off], rbx",    {0x48,0x01,0x1D,0x78,0x56,0x34,0x12}, 7, 3},

    /* IMUL r, r/m, imm32 (0x69) */
    {"IMUL rcx, [rip+off], 5", {0x48,0x69,0x0D,0x78,0x56,0x34,0x12,0x05,0x00,0x00,0x00}, 11, 3},

    /* IMUL r, r/m, imm8 (0x6B) */
    {"IMUL rax, [rip+off], 5", {0x48,0x6B,0x05,0x78,0x56,0x34,0x12,0x05}, 8, 3},

    /* MOVSXD (0x63) */
    {"MOVSXD rax, [rip+off]", {0x48,0x63,0x05,0x78,0x56,0x34,0x12}, 7, 3},

    /* CMPXCHG (0F B0/B1) */
    {"CMPXCHG [rdx], eax",    {0x0F,0xB1,0x02}, 3, -1},

    /* SHL r/m, imm8 (0xC1) */
    {"SHL rax, 3",            {0x48,0xC1,0xE0,0x03}, 4, -1},

    /* MOV r/m8, imm8 (0xC6) */
    {"MOV byte [rax], 0",     {0xC6,0x00,0x00}, 3, -1},

    /* SHR r/m32, 1 (0xD1) */
    {"SHR rax, 1",            {0x48,0xD1,0xE8}, 3, -1},

    /* SHR r/m32, CL (0xD3) */
    {"SHR rax, cl",           {0x48,0xD3,0xE8}, 3, -1},

    /* Group 4 INC r/m8 (0xFE) */
    {"INC byte [rax]",        {0xFE,0x00}, 2, -1},

    /* INC r/m64 (0xFF /0) */
    {"INC qword [rdx]",       {0x48,0xFF,0x02}, 3, -1},

    /* MOV Sreg, r/m16 (0x8E) */
    {"MOV ss, ax",            {0x8E,0xD0}, 2, -1},

    /* MOV r/m16, Sreg (0x8C) */
    {"MOV [rax], ss",         {0x8C,0x10}, 2, -1},
};

#define N_TESTS (sizeof(tests) / sizeof(tests[0]))

int main(void)
{
    int passed = 0, failed = 0;

    printf("Testing x64 instruction decoder (%zu tests)\n\n", N_TESTS);

    for (size_t i = 0; i < N_TESTS; i++) {
        testcase *t = &tests[i];
        int len = inst_len(t->bytes);
        int rip = rip_disp_off(t->bytes);
        int len_ok = (len == t->expected_len);
        int rip_ok = (rip == t->expected_rip);

        if (len_ok && rip_ok) {
            printf("  PASS  %s (len=%d, rip=%d)\n", t->name, len, rip);
            passed++;
        } else {
            printf("  FAIL  %s\n", t->name);
            if (!len_ok)
                printf("         len: got %d, expected %d\n", len, t->expected_len);
            if (!rip_ok)
                printf("         rip: got %d, expected %d\n", rip, t->expected_rip);
            failed++;
        }
    }

    printf("\n%d passed, %d failed out of %zu\n", passed, failed, N_TESTS);
    return failed ? 1 : 0;
}
