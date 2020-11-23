
#include <cstdio>
#include <Windows.h>
#include <tchar.h>
#include <psapi.h>
#include <cstring>
#include "DLL Injector.h"

const char* path = "C:\\Users\\Sophie\\source\\repos\\Function hooking\\Debug\\Function hooking DLL.dll";
const TCHAR* process = L"Function hooking.exe";

int FindTargetProcessPID(TCHAR* processName) {
	TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
	DWORD aProcesses[1024], cbNeeded, cProcesses;
	unsigned int i;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		return -1;
	}

	cProcesses = cbNeeded / sizeof(DWORD);

	for (i = 0; i < cProcesses; i++)
	{
		if (aProcesses[i] != 0)
		{
			HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
				PROCESS_VM_READ,
				FALSE, aProcesses[i]);
			if (NULL != hProcess)
			{
				HMODULE hMod;
				DWORD cbNeeded;

				if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
					&cbNeeded))
				{
					GetModuleBaseName(hProcess, hMod, szProcessName,
						sizeof(szProcessName) / sizeof(TCHAR));
				}
				if (_tcscmp(szProcessName, processName) == 0)
				{
					CloseHandle(hProcess);
					return aProcesses[i];
				}
			}
			CloseHandle(hProcess);
		}
	}
	return -1;
}

HANDLE RequestHandleToProcess(int PID)
{
	HANDLE processHandle = OpenProcess(PROCESS_CREATE_THREAD |
		PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION |
		PROCESS_VM_WRITE |
		PROCESS_VM_READ,
		FALSE,
		PID);

	if (processHandle == NULL)
	{
		printf("%s\n", "Couldn't obtain an handle to the process.");
		exit(1);
	}

	return processHandle;
}

LPVOID AllocateRemoteProcessMemory(const HANDLE& processHandle)
{
	LPVOID allocatedMemoryLocation = VirtualAllocEx(processHandle, 0, strlen(path) + 1,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE);

	if (allocatedMemoryLocation == NULL)
	{
		printf("%s", "Couldn't allocate memory on the process.\n");
		exit(1);
	}
	return allocatedMemoryLocation;
}

void WriteDllPathToRemoteProcess(const HANDLE& processHandle, const LPVOID& allocatedMemoryLocation, const char* path)
{
	if (!WriteProcessMemory(processHandle, allocatedMemoryLocation, path, strlen(path) + 1, NULL))
	{
		printf("%s", "Couldn't write into the process.\n");
		exit(1);
	}
}

void RunRemoteThread(const HANDLE& processHandle, const LPVOID& allocatedMemoryLocation)
{
	HMODULE kernel32Module = GetModuleHandle(L"kernel32.dll");
	LPVOID loadLibraryAddress = GetProcAddress(kernel32Module, "LoadLibraryA");
	if (CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddress, allocatedMemoryLocation, 0, NULL) != NULL)
	{
		printf("%s", "DLL successfully injected.\n");
	}
}


int main(int argc, int** argv)
{
	int PID = FindTargetProcessPID((TCHAR*)process);

	if (PID == -1)
	{
		printf("%s\n", "Couldn't find the target process.");
		exit(1);
	}
	HANDLE processHandle = RequestHandleToProcess(PID);

	LPVOID allocatedMemoryLocation = AllocateRemoteProcessMemory(processHandle);

	WriteDllPathToRemoteProcess(processHandle, allocatedMemoryLocation, path);

	RunRemoteThread(processHandle, allocatedMemoryLocation);

	CloseHandle(processHandle);
}

