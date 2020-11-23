#pragma once

void RunRemoteThread(const HANDLE& processHandle, const LPVOID& allocatedMemoryLocation);

void WriteDllPathToRemoteProcess(const HANDLE& processHandle, const LPVOID& allocatedMemoryLocation, const char* path);

void OpenRemoteProcess(int PID, const HANDLE& processHandle);

void AllocateRemoteProcessMemory(const HANDLE& processHandle, const LPVOID& allocatedMemoryLocation);
