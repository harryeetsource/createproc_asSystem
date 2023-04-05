#include <Windows.h>

#include <sddl.h>

#include <AccCtrl.h>

#include <AclAPI.h>

bool IsRunningAsSystem() {
    HANDLE hToken = NULL;
    PTOKEN_USER pTokenUser = NULL;
    DWORD dwSize = 0;
    LPWSTR szSID = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return false;
    }

    if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize) && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        pTokenUser = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), 0, dwSize);
    }

    if (!pTokenUser) {
        CloseHandle(hToken);
        return false;
    }

    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
        HeapFree(GetProcessHeap(), 0, pTokenUser);
        CloseHandle(hToken);
        return false;
    }

    if (!ConvertSidToStringSidW(pTokenUser->User.Sid, &szSID)) {
        HeapFree(GetProcessHeap(), 0, pTokenUser);
        CloseHandle(hToken);
        return false;
    }

    bool isSystem = (wcscmp(szSID, L"S-1-5-18") == 0);

    LocalFree(szSID);
    HeapFree(GetProcessHeap(), 0, pTokenUser);
    CloseHandle(hToken);

    return isSystem;
}

bool CheckAdmin() {
    BOOL fIsRunAsAdmin = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    PSID pAdministratorsGroup = NULL;

    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &pAdministratorsGroup)) {
        dwError = GetLastError();
        goto Cleanup;
    }

    if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin)) {
        dwError = GetLastError();
        goto Cleanup;
    }

Cleanup:
    if (pAdministratorsGroup) {
        FreeSid(pAdministratorsGroup);
        pAdministratorsGroup = NULL;
    }

    if (ERROR_SUCCESS != dwError) {
        throw std::runtime_error("CheckAdmin failed.");
    }

    return fIsRunAsAdmin;
}

// Get the current executable's path
std::string getExecutablePath() {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    return std::string(path);
}

// Create a process with NT Authority/System privileges
void createSystemProcess(const std::string& exePath) {
    // Open a handle to the SYSTEM account's token
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &token)) {
        std::cerr << "Error: Failed to open process token. Error code: " << GetLastError() << std::endl;
        return;
    }

    // Duplicate the token
    SECURITY_ATTRIBUTES securityAttributes = {0};
    securityAttributes.nLength = sizeof(securityAttributes);
    HANDLE newToken;
    if (!DuplicateTokenEx(token, MAXIMUM_ALLOWED, &securityAttributes, SecurityImpersonation, TokenPrimary, &newToken)) {
        std::cerr << "Error: Failed to duplicate token. Error code: " << GetLastError() << std::endl;
        CloseHandle(token);
        return;
    }

    // Create the new process using the duplicated token
    STARTUPINFOA startupInfo = {0};
    startupInfo.cb = sizeof(startupInfo);
    PROCESS_INFORMATION processInfo = {0};

    if (!CreateProcessAsUserA(newToken, exePath.c_str(), NULL, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo)) {
        std::cerr << "Error: Failed to create process as user. Error code: " << GetLastError() << std::endl;
    } else {
        // Close process and thread handles
        CloseHandle(processInfo.hProcess);
        CloseHandle(processInfo.hThread);
    }

    // Close the token handles
    CloseHandle(newToken);
    CloseHandle(token);
}
