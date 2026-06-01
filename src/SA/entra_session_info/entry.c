#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include <ntsecapi.h>

// AAD join structs (same as aadjoininfo)
typedef enum _DSREG_JOIN_TYPE {
    DSREG_UNKNOWN_JOIN = 0,
    DSREG_DEVICE_JOIN = 1,
    DSREG_WORKPLACE_JOIN = 2
} DSREG_JOIN_TYPE;

typedef struct _DSREG_USER_INFO {
    LPWSTR pszUserEmail;
    LPWSTR pszUserKeyId;
    LPWSTR pszUserKeyName;
} DSREG_USER_INFO;

typedef struct _DSREG_JOIN_INFO {
    DSREG_JOIN_TYPE joinType;
    PCCERT_CONTEXT pJoinCertificate;
    LPWSTR pszDeviceId;
    LPWSTR pszIdpDomain;
    LPWSTR pszTenantId;
    LPWSTR pszJoinUserEmail;
    LPWSTR pszTenantDisplayName;
    LPWSTR pszMdmEnrollmentUrl;
    LPWSTR pszMdmTermsOfUseUrl;
    LPWSTR pszMdmComplianceUrl;
    LPWSTR pszUserSettingSyncUrl;
    DSREG_USER_INFO *pUserInfo;
} DSREG_JOIN_INFO, *PDSREG_JOIN_INFO;

WINBASEAPI DWORD WINAPI NETAPI32$NetGetAadJoinInformation(LPCWSTR pcszTenantId, PDSREG_JOIN_INFO *ppJoinInfo);
WINBASEAPI VOID WINAPI NETAPI32$NetFreeAadJoinInformation(PDSREG_JOIN_INFO pJoinInfo);

WINBASEAPI DWORD WINAPI KERNEL32$GetFileAttributesA(LPCSTR lpFileName);
WINBASEAPI char* __cdecl MSVCRT$strncpy(char* __restrict__ _Dest, const char* __restrict__ _Source, size_t _Count);

// Get environment variable (ANSI) from process block
BOOL GetEnvVarA(const char* name, char* out, DWORD outSize)
{
    LPSTR env = (LPSTR)KERNEL32$GetEnvironmentStrings();
    if (!env) return FALSE;
    LPSTR p = env;
    DWORD nameLen = MSVCRT$strlen(name);
    while (*p) {
        if (MSVCRT$_strnicmp(p, name, nameLen) == 0 && p[nameLen] == '=') {
            MSVCRT$strncpy(out, p + nameLen + 1, outSize - 1);
            out[outSize - 1] = '\0';
            KERNEL32$FreeEnvironmentStringsA(env);
            return TRUE;
        }
        p += MSVCRT$strlen(p) + 1;
    }
    KERNEL32$FreeEnvironmentStringsA(env);
    return FALSE;
}

// Check file/dir existence using CreateFileA (already in bofdefs.h)
BOOL FileExistsA(const char* path)
{
    HANDLE h = KERNEL32$CreateFileA(path, 0, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) { KERNEL32$CloseHandle(h); return TRUE; }
    return FALSE;
}

BOOL DirExistsA(const char* path)
{
    DWORD attr = KERNEL32$GetFileAttributesA(path);
    return (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY));
}

void RunEntraSessionInfo()
{
    // Heap-allocate all large buffers to keep stack tiny (< 1KB) and avoid __chkstk_ms
    char* localAppData = (char*)intAlloc(512);
    char* userProfile  = (char*)intAlloc(512);
    char* teamsPath    = (char*)intAlloc(512);
    char* odPath       = (char*)intAlloc(512);
    char* azureProfile = (char*)intAlloc(512);
    char* azCtx        = (char*)intAlloc(512);
    WCHAR* tenantName  = (WCHAR*)intAlloc(256 * sizeof(WCHAR));
    WCHAR* tenantId    = (WCHAR*)intAlloc(128 * sizeof(WCHAR));
    WCHAR* deviceId    = (WCHAR*)intAlloc(128 * sizeof(WCHAR));
    WCHAR* upn         = (WCHAR*)intAlloc(256 * sizeof(WCHAR));
    char* userName     = (char*)intAlloc(256);
    char* authPackage  = (char*)intAlloc(64);
    char* logonDomain  = (char*)intAlloc(64);

    if (!localAppData || !userProfile || !teamsPath || !odPath || !azureProfile || !azCtx ||
        !tenantName || !tenantId || !deviceId || !upn || !userName || !authPackage || !logonDomain) {
        internal_printf("[-] Memory allocation failed\n");
        goto cleanup;
    }

    internal_printf("[*] Analyzing local Entra ID / cloud access profile...\n\n");
    printoutput(FALSE);

    // 1. AAD Join
    internal_printf("================== Device / Join Info ==================\n");
    PDSREG_JOIN_INFO pJoinInfo = NULL;
    BOOL aadJoined = FALSE;
    DWORD res = NETAPI32$NetGetAadJoinInformation(NULL, &pJoinInfo);
    if (res == 0 && pJoinInfo != NULL) {
        aadJoined = TRUE;
        if (pJoinInfo->pszTenantDisplayName) MSVCRT$wcscpy_s(tenantName, 256, pJoinInfo->pszTenantDisplayName);
        if (pJoinInfo->pszTenantId) MSVCRT$wcscpy_s(tenantId, 128, pJoinInfo->pszTenantId);
        if (pJoinInfo->pszDeviceId) MSVCRT$wcscpy_s(deviceId, 128, pJoinInfo->pszDeviceId);
        if (pJoinInfo->pszJoinUserEmail) MSVCRT$wcscpy_s(upn, 256, pJoinInfo->pszJoinUserEmail);
        NETAPI32$NetFreeAadJoinInformation(pJoinInfo);
    }
    internal_printf("AzureAdJoined  : %s\n", aadJoined ? "YES" : "NO");
    if (aadJoined) {
        internal_printf("Tenant Name    : %S\n", tenantName);
        internal_printf("Tenant ID      : %S\n", tenantId);
        internal_printf("Device ID      : %S\n", deviceId);
        internal_printf("UPN            : %S\n", upn);
    }
    printoutput(FALSE);

    // 2. Logon session (exact pattern from get_session_info)
    internal_printf("\n====================== User / SSO ======================\n");
    HANDLE token = NULL;
    PSECURITY_LOGON_SESSION_DATA pLogonSessionData = NULL;
    if (ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_STATISTICS stats = {0};
        DWORD len = 0;
        if (ADVAPI32$GetTokenInformation(token, TokenStatistics, &stats, sizeof(stats), &len)) {
            NTSTATUS status = SECUR32$LsaGetLogonSessionData(&(stats.AuthenticationId), &pLogonSessionData);
            if (status == 0 && pLogonSessionData) {
                if (pLogonSessionData->UserName.Buffer && pLogonSessionData->UserName.Length > 0) {
                    int l = pLogonSessionData->UserName.Length / sizeof(WCHAR);
                    if (l > 255) l = 255;
                    Kernel32$WideCharToMultiByte(CP_UTF8, 0, pLogonSessionData->UserName.Buffer, l, userName, 256, NULL, NULL);
                    userName[l] = '\0';
                }
                if (pLogonSessionData->LogonDomain.Buffer && pLogonSessionData->LogonDomain.Length > 0) {
                    int l = pLogonSessionData->LogonDomain.Length / sizeof(WCHAR);
                    if (l > 63) l = 63;
                    Kernel32$WideCharToMultiByte(CP_UTF8, 0, pLogonSessionData->LogonDomain.Buffer, l, logonDomain, 64, NULL, NULL);
                    logonDomain[l] = '\0';
                }
                if (pLogonSessionData->AuthenticationPackage.Buffer && pLogonSessionData->AuthenticationPackage.Length > 0) {
                    int l = pLogonSessionData->AuthenticationPackage.Length / sizeof(WCHAR);
                    if (l > 63) l = 63;
                    Kernel32$WideCharToMultiByte(CP_UTF8, 0, pLogonSessionData->AuthenticationPackage.Buffer, l, authPackage, 64, NULL, NULL);
                    authPackage[l] = '\0';
                }
                internal_printf("User           : %s\\%s\n", logonDomain, userName);
                internal_printf("Auth Package   : %s\n", authPackage);
                SECUR32$LsaFreeReturnBuffer(pLogonSessionData);
            }
        }
        KERNEL32$CloseHandle(token);
    }
    printoutput(FALSE);

    // 3. PRT
    BOOL prtPresent = FALSE;
    HKEY hKey = NULL;
    if (ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\TokenBroker", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        prtPresent = TRUE;
        ADVAPI32$RegCloseKey(hKey);
    }
    internal_printf("PRT Present    : %s\n", prtPresent ? "YES" : "NO");
    printoutput(FALSE);

    // 4. Office identities
    internal_printf("\n================= Cached Work Accounts =================\n");
    BOOL hasOffice365 = FALSE;
    if (ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Office\\16.0\\Common\\Identity\\Identities", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD idx = 0;
        char subKeyName[256];
        DWORD subKeyLen = 256;
        while (ADVAPI32$RegEnumKeyExA(hKey, idx, subKeyName, &subKeyLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            HKEY hSub = NULL;
            if (ADVAPI32$RegOpenKeyExA(hKey, subKeyName, 0, KEY_READ, &hSub) == ERROR_SUCCESS) {
                char email[256] = {0};
                DWORD type = 0, size = 255;
                if (ADVAPI32$RegQueryValueExA(hSub, "EmailAddress", NULL, &type, (LPBYTE)email, &size) == ERROR_SUCCESS) {
                    if (MSVCRT$strlen(email) > 0) hasOffice365 = TRUE;
                }
                ADVAPI32$RegCloseKey(hSub);
            }
            idx++;
            subKeyLen = 256;
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    internal_printf("Office 365     : %s\n", hasOffice365 ? "YES" : "NO");
    printoutput(FALSE);

    // 5. Teams / OneDrive (file existence via heap buffers)
    GetEnvVarA("LOCALAPPDATA", localAppData, 512);
    GetEnvVarA("USERPROFILE", userProfile, 512);

    BOOL hasTeams = FALSE;
    BOOL hasOneDriveBiz = FALSE;
    if (localAppData[0]) {
        MSVCRT$sprintf(teamsPath, "%s\\Microsoft\\Teams", localAppData);
        if (DirExistsA(teamsPath)) hasTeams = TRUE;

        MSVCRT$sprintf(odPath, "%s\\Microsoft\\OneDrive\\settings\\Business1", localAppData);
        if (DirExistsA(odPath)) hasOneDriveBiz = TRUE;
    }
    internal_printf("Teams          : %s\n", hasTeams ? "YES" : "NO");
    internal_printf("OneDrive Biz   : %s\n", hasOneDriveBiz ? "YES" : "NO");
    printoutput(FALSE);

    // 6. Edge work profiles
    int edgeProfiles = 0;
    if (ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Edge\\Profiles", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD idx = 0;
        char subKeyName[256];
        DWORD subKeyLen = 256;
        while (ADVAPI32$RegEnumKeyExA(hKey, idx, subKeyName, &subKeyLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            HKEY hSub = NULL;
            if (ADVAPI32$RegOpenKeyExA(hKey, subKeyName, 0, KEY_READ, &hSub) == ERROR_SUCCESS) {
                WCHAR userNameW[256] = {0};
                DWORD type = 0, size = sizeof(userNameW);
                if (ADVAPI32$RegQueryValueExW(hSub, L"UserName", NULL, &type, (LPBYTE)userNameW, &size) == ERROR_SUCCESS) {
                    if (MSVCRT$wcslen(userNameW) > 0 && MSVCRT$wcschr(userNameW, L'@')) edgeProfiles++;
                }
                ADVAPI32$RegCloseKey(hSub);
            }
            idx++;
            subKeyLen = 256;
        }
        ADVAPI32$RegCloseKey(hKey);
    }
    internal_printf("Edge Work Prof : %d\n", edgeProfiles);
    printoutput(FALSE);

    // 7. Azure tooling (file existence only)
    internal_printf("\n================== Azure Admin Context =================\n");
    BOOL hasAzureCLI = FALSE;
    BOOL hasAzPowerShell = FALSE;
    if (userProfile[0]) {
        MSVCRT$sprintf(azureProfile, "%s\\.azure\\azureProfile.json", userProfile);
        if (FileExistsA(azureProfile)) hasAzureCLI = TRUE;

        MSVCRT$sprintf(azCtx, "%s\\.Azure\\AzContext.json", userProfile);
        if (FileExistsA(azCtx)) hasAzPowerShell = TRUE;
    }
    internal_printf("Azure CLI      : %s\n", hasAzureCLI ? "YES" : "NO");
    internal_printf("Az PowerShell  : %s\n", hasAzPowerShell ? "YES" : "NO");
    printoutput(FALSE);

    // 8. Summary
    internal_printf("\n============================ SUMMARY ============================\n");
    internal_printf("AAD Joined     : %s\n", aadJoined ? "YES" : "NO");
    if (aadJoined) {
        internal_printf("Tenant         : %S\n", tenantName);
        internal_printf("Tenant ID      : %S\n", tenantId);
    }
    internal_printf("User           : %s\\%s\n", logonDomain, userName);
    internal_printf("PRT            : %s\n", prtPresent ? "YES" : "NO");
    internal_printf("Office 365     : %s\n", hasOffice365 ? "YES" : "NO");
    internal_printf("Teams          : %s\n", hasTeams ? "YES" : "NO");
    internal_printf("OneDrive Biz   : %s\n", hasOneDriveBiz ? "YES" : "NO");
    internal_printf("Edge Profiles  : %d\n", edgeProfiles);
    internal_printf("Azure CLI      : %s\n", hasAzureCLI ? "YES" : "NO");
    internal_printf("Az PowerShell  : %s\n", hasAzPowerShell ? "YES" : "NO");
    internal_printf("=================================================================\n");

cleanup:
    intFree(localAppData); intFree(userProfile); intFree(teamsPath); intFree(odPath);
    intFree(azureProfile); intFree(azCtx); intFree(tenantName); intFree(tenantId);
    intFree(deviceId); intFree(upn); intFree(userName); intFree(authPackage); intFree(logonDomain);
}

#ifdef BOF
VOID go(IN PCHAR Buffer, IN ULONG Length)
{
    if (!bofstart()) return;
    RunEntraSessionInfo();
    printoutput(TRUE);
}
#else
int main()
{
    RunEntraSessionInfo();
    return 0;
}
#endif
