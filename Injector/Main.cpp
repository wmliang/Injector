#include <stdio.h>
#include <windows.h>

BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if(!LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
	{
		printf("Error (%d)\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if(bEnablePrivilege)
	{
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	else
	{
		tp.Privileges[0].Attributes = 0;
	}

	if(!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
	{
		printf("Error adjusting privilege (%d)\n", GetLastError());
		return FALSE;
	}

	if(GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		printf("Not all privilges available\n");
		return FALSE;
	}

	return TRUE;
}

DWORD InjectDLL(UINT32 pid, PCHAR dll)
{
	CHAR path[MAX_PATH];
	GetFullPathName(dll, MAX_PATH, path, nullptr);

	HANDLE hToken;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);

    SetPrivilege(hToken, SE_DEBUG_NAME, TRUE);

	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
	if(hProcess)
	{
		size_t strSize = (strlen(path) + 1) * sizeof(TCHAR);
		LPVOID pBuf = VirtualAllocEx(hProcess, 0, strSize, MEM_COMMIT, PAGE_READWRITE);
		if(pBuf == NULL)
		{
			printf("Couldn't allocate memory in process\n");
			return 1;
		}
		SIZE_T written;
		if (!WriteProcessMemory(hProcess, pBuf, path, strSize, &written))
		{
			printf("Couldn't write to process memory\n");
			return 1;
		}

		LPVOID pLoadLibraryA = GetProcAddress(GetModuleHandle("kernel32"), "LoadLibraryA");

		if(!CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pBuf, 0, NULL))
		{
			printf("Couldn't create remote thread (%d)\n", GetLastError());
		}
		else
		{
			printf("DLL injected\n");
		}
	}
	else
	{
		printf("Couldn't open process (%d)\n", GetLastError());
	}

	return 0;
}

DWORD InjectCMD(UINT32 pid, PCHAR cmd)
{
	HANDLE hToken;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);

    SetPrivilege(hToken, SE_DEBUG_NAME, TRUE);

	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
	if(hProcess)
	{
		size_t strSize = (strlen(cmd) + 1) * sizeof(TCHAR);
		LPVOID pBuf = VirtualAllocEx(hProcess, 0, strSize, MEM_COMMIT, PAGE_READWRITE);
		if(pBuf == NULL)
		{
			printf("Couldn't allocate memory in process\n");
			return 1;
		}
		SIZE_T written;
		if (!WriteProcessMemory(hProcess, pBuf, cmd, strSize, &written))
		{
			printf("Couldn't write to process memory\n");
			return 1;
		}

		LPVOID pLoadLibraryA = GetProcAddress(GetModuleHandle("kernel32"), "WinExec");

		if(!CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pBuf, 0, NULL))
		{
			printf("Couldn't create remote thread (%d)\n", GetLastError());
		}
		else
		{
			printf("CMD executed\n");
		}
	}
	else
	{
		printf("Couldn't open process (%d)\n", GetLastError());
	}

	return 0;
}

/*
 * Inject and execute a DLL into process
 */
int main(int argc, char *argv[])
{
	if(argc != 3) {
		printf("Usage: %s <PID> <DLL Path|CMD>\n", argv[0]);
		return 0;
	}
	if(strlen(argv[2]) > 4 && !strcmp(".dll", argv[2]+strlen(argv[2])-4)) {
		printf("Injecting DLL = %s\n", argv[2]);
		InjectDLL(atoi(argv[1]), argv[2]);
	} else {
		printf("Executing CMD = %s\n", argv[2]);
		InjectCMD(atoi(argv[1]), argv[2]);
	}
    return 0;
}