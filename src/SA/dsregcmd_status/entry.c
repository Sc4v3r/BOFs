#include <windows.h>
#include "bofdefs.h"
#include "base.c"

// APIs not in common bofdefs.h
WINBASEAPI WINBOOL WINAPI KERNEL32$CreatePipe(PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize);
WINBASEAPI WINBOOL WINAPI KERNEL32$CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, WINBOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
WINBASEAPI WINBOOL WINAPI KERNEL32$PeekNamedPipe(HANDLE hNamedPipe, LPVOID lpBuffer, DWORD nBufferSize, LPDWORD lpBytesRead, LPDWORD lpTotalBytesAvail, LPDWORD lpBytesLeftThisMessage);
WINBASEAPI WINBOOL WINAPI KERNEL32$GetExitCodeProcess(HANDLE hProcess, LPDWORD lpExitCode);

BOOL IsUtf16Le(const char* data, DWORD len)
{
    return (len >= 2 && (BYTE)data[0] == 0xFF && (BYTE)data[1] == 0xFE);
}

void PrintUtf16Le(const char* data, DWORD len)
{
    if (len < 2) return;
    int wideCount = (int)((len - 2) / sizeof(WCHAR));
    if (wideCount <= 0) return;

    WCHAR* wideStr = (WCHAR*)(data + 2);
    int utf8Len = Kernel32$WideCharToMultiByte(CP_UTF8, 0, wideStr, wideCount, NULL, 0, NULL, NULL);
    if (utf8Len <= 0) return;

    char* utf8 = (char*)intAlloc(utf8Len + 1);
    if (!utf8) return;

    Kernel32$WideCharToMultiByte(CP_UTF8, 0, wideStr, wideCount, utf8, utf8Len, NULL, NULL);
    utf8[utf8Len] = '\0';
    internal_printf("%s", utf8);
    intFree(utf8);
}

BOOL RunCommand(LPSTR cmdLine, DWORD* pExitCode)
{
    HANDLE hReadPipe = NULL;
    HANDLE hWritePipe = NULL;
    SECURITY_ATTRIBUTES sa;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    DWORD bufSize = 8192;
    char* accum = (char*)intAlloc(bufSize);
    DWORD total = 0;
    BOOL success = FALSE;

    *pExitCode = 0;
    if (!accum) return FALSE;

    MSVCRT$memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    if (!KERNEL32$CreatePipe(&hReadPipe, &hWritePipe, &sa, 0))
    {
        internal_printf("[-] CreatePipe failed: %lu\n", KERNEL32$GetLastError());
        intFree(accum);
        return FALSE;
    }

    MSVCRT$memset(&si, 0, sizeof(si));
    si.cb = sizeof(STARTUPINFOA);
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.dwFlags = STARTF_USESTDHANDLES;

    MSVCRT$memset(&pi, 0, sizeof(pi));

    success = KERNEL32$CreateProcessA(NULL, cmdLine, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    KERNEL32$CloseHandle(hWritePipe);

    if (!success)
    {
        KERNEL32$CloseHandle(hReadPipe);
        intFree(accum);
        return FALSE;
    }

    while (1)
    {
        DWORD avail = 0;
        if (!KERNEL32$PeekNamedPipe(hReadPipe, NULL, 0, NULL, &avail, NULL))
            break;
        if (avail == 0)
        {
            if (KERNEL32$WaitForSingleObject(pi.hProcess, 100) != WAIT_TIMEOUT)
                break;
            continue;
        }

        if (total + avail + 1 > bufSize)
        {
            bufSize = total + avail + 8192;
            char* newBuf = (char*)intRealloc(accum, bufSize);
            if (!newBuf) break;
            accum = newBuf;
        }

        DWORD read = 0;
        if (!KERNEL32$ReadFile(hReadPipe, accum + total, avail, &read, NULL) || read == 0)
            break;
        total += read;
    }

    accum[total] = '\0';

    KERNEL32$GetExitCodeProcess(pi.hProcess, pExitCode);
    KERNEL32$CloseHandle(pi.hThread);
    KERNEL32$CloseHandle(pi.hProcess);
    KERNEL32$CloseHandle(hReadPipe);

    if (total > 0)
    {
        if (IsUtf16Le(accum, total))
        {
            PrintUtf16Le(accum, total);
        }
        else
        {
            internal_printf("%s", accum);
        }
    }

    intFree(accum);
    return TRUE;
}

void RunDsregcmdStatus()
{
    DWORD exitCode = 0;
    BOOL ok = FALSE;

    // Attempt 1: direct execution
    CHAR cmd1[] = "dsregcmd.exe /status";
    ok = RunCommand(cmd1, &exitCode);
    if (ok && exitCode == 0) return;

    // Attempt 2: explicit System32 path (native x64)
    if (!ok || exitCode != 0)
    {
        internal_printf("[*] Trying System32 path...\n");
        CHAR cmd2[] = "C:\\Windows\\System32\\dsregcmd.exe /status";
        ok = RunCommand(cmd2, &exitCode);
        if (ok && exitCode == 0) return;
    }

    // Attempt 3: Sysnative path (WOW64 x86 beacon on x64 host)
    if (!ok || exitCode != 0)
    {
        internal_printf("[*] Trying Sysnative path...\n");
        CHAR cmd3[] = "C:\\Windows\\Sysnative\\dsregcmd.exe /status";
        ok = RunCommand(cmd3, &exitCode);
        if (ok && exitCode == 0) return;
    }

    // Attempt 4: through cmd.exe (handles console/encoding edge cases)
    if (!ok || exitCode != 0)
    {
        internal_printf("[*] Trying via cmd.exe...\n");
        CHAR cmd4[] = "cmd.exe /c dsregcmd.exe /status";
        ok = RunCommand(cmd4, &exitCode);
        if (ok && exitCode == 0) return;
    }

    if (!ok)
    {
        internal_printf("[-] All execution attempts failed (check architecture / WOW64).\n");
    }
    else if (exitCode != 0)
    {
        internal_printf("[-] dsregcmd exited with code %lu on all attempts.\n", exitCode);
    }
}

#ifdef BOF
VOID go(IN PCHAR Buffer, IN ULONG Length)
{
    if (!bofstart()) return;
    RunDsregcmdStatus();
    printoutput(TRUE);
}
#else
int main()
{
    RunDsregcmdStatus();
    return 0;
}
#endif
