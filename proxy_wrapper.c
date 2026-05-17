#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

static void usage(void)
{
    fprintf(stderr,
        "Usage: proxy_wrapper.exe -proxy=IP:PORT -target=PATH [target args...]\n"
        "\n"
        "Wraps an executable in a SOCKS5 proxy by hooking its Winsock connect() calls\n"
        "via DLL injection.\n"
        "\n"
        "Examples:\n"
        "  proxy_wrapper.exe -proxy=127.0.0.1:1080 -target=chrome.exe\n"
        "  proxy_wrapper.exe -proxy=192.168.1.50:9050 -target=\"C:\\Program Files\\Firefox\\firefox.exe\"\n"
    );
}

int main(int argc, char *argv[])
{
    const char *proxy = NULL;
    const char *target = NULL;
    int target_idx = 0;

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "-proxy=", 7) == 0) {
            proxy = argv[i] + 7;
        } else if (strncmp(argv[i], "-target=", 8) == 0) {
            target = argv[i] + 8;
            target_idx = i;
        }
    }

    if (!proxy || !target) {
        usage();
        return 1;
    }

    SetEnvironmentVariableA("PROXY_WRAPPER_PROXY", proxy);

    char cmdline[32768];
    cmdline[0] = 0;
    if (strchr(target, ' ')) {
        cmdline[0] = '"';
        strcpy(cmdline + 1, target);
        strcat(cmdline, "\"");
    } else {
        strcpy(cmdline, target);
    }
    for (int i = target_idx + 1; i < argc; i++) {
        strcat(cmdline, " ");
        strcat(cmdline, argv[i]);
    }

    char dll_path[MAX_PATH];
    {
        char exe_path[MAX_PATH];
        GetModuleFileNameA(NULL, exe_path, sizeof(exe_path));
        char *sep = strrchr(exe_path, '\\');
        if (sep) *sep = 0;
        snprintf(dll_path, sizeof(dll_path), "%s\\socks_hook.dll", exe_path);
    }

    STARTUPINFOA si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "Error: failed to launch target (code %lu)\n", GetLastError());
        return 1;
    }

    size_t dll_len = strlen(dll_path) + 1;
    void *remote = VirtualAllocEx(pi.hProcess, NULL, dll_len, MEM_COMMIT, PAGE_READWRITE);
    if (!remote) {
        fprintf(stderr, "Error: VirtualAllocEx failed (code %lu)\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    WriteProcessMemory(pi.hProcess, remote, dll_path, dll_len, NULL);

    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC proc = GetProcAddress(kernel32, "LoadLibraryA");
    LPTHREAD_START_ROUTINE loadlib;
    memcpy(&loadlib, &proc, sizeof(loadlib));

    HANDLE rt = CreateRemoteThread(pi.hProcess, NULL, 0, loadlib, remote, 0, NULL);
    if (!rt) {
        fprintf(stderr, "Error: CreateRemoteThread failed (code %lu)\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    WaitForSingleObject(rt, INFINITE);
    CloseHandle(rt);
    VirtualFreeEx(pi.hProcess, remote, 0, MEM_RELEASE);

    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return (int)exit_code;
}
