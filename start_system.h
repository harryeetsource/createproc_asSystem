#ifndef SYSTEM_UTILS_H
#define SYSTEM_UTILS_H

#include <Windows.h>
#include <sddl.h>
#include <AccCtrl.h>
#include <AclAPI.h>
#include <string>
#include <stdexcept>
#include <iostream>

namespace SystemUtils {
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
        if (!DuplicateTokenEx(token, SecurityImpersonation, &securityAttributes, SecurityIdentification, TokenPrimary, &newToken)) {
        std::cerr << "Error: Failed to duplicate token. Error code: " << GetLastError() << std::endl;
        CloseHandle(token);
        return;
        }
    // Change the token's session ID to match the current process
    DWORD sessionId;
    DWORD sessionSize = sizeof(sessionId);
    if (!GetTokenInformation(token, TokenSessionId, &sessionId, sizeof(sessionId), &sessionSize)) {
        std::cerr << "Error: Failed to get token session ID. Error code: " << GetLastError() << std::endl;
        CloseHandle(newToken);
        CloseHandle(token);
        return;
    }

    if (!SetTokenInformation(newToken, TokenSessionId, &sessionId, sizeof(sessionId))) {
        std::cerr << "Error: Failed to set token session ID. Error code: " << GetLastError() << std::endl;
        CloseHandle(newToken);
        CloseHandle(token);
        return;
    }

    // Launch the new process with the duplicated token
    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};

    if (!CreateProcessAsUserA(newToken, NULL, const_cast<char*>(exePath.c_str()), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        std::cerr << "Error: Failed to create process. Error code: " << GetLastError() << std::endl;
        CloseHandle(newToken);
        CloseHandle(token);
        return;
    }

    // Close the handles
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(newToken);
    CloseHandle(token);
}
} // namespace SystemUtils
#endif // SYSTEM_UTILS_H
