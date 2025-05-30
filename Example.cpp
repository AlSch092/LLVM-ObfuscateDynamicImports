#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <iostream>

const char* g_ImportNames[] =
{
	"NtQueryInformationProcess",
	"NtQuerySystemInformation",
	"NtQueryVirtualMemory",
	"NtQueryInformationThread",
	"NtQueryVolumeInformationFile",
	"NtCreateSection",
	"NtCreateThread",
	"NtCreateProcessEx",
	"NtQueueApcThread",
	"NtWriteVirtualMemory",
	"NtReadVirtualMemory",
	"NtOpenProcess"
};

FARPROC g_ImportAddresses[sizeof(g_ImportNames) / sizeof(char*)];

__attribute__((annotate("resolves-imports")))
bool GetImportAddresses()
{
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	
	if(!ntdll)
	{
		printf("Failed to find ntdll.dll module!\n");
		return false;
	}
	
	for (int i = 0; i < sizeof(g_ImportNames) / sizeof(char*); i++)
	{
		const char* importName = g_ImportNames[i];
		auto addr = GetProcAddress(ntdll, importName);
		printf("%s -> %llX\n", importName, (ULONGLONG)addr);
		g_ImportAddresses[i] = addr;
	}

	return true;
}

__attribute__((annotate("returns-imports")))
FARPROC GetImportAddress(const int index)
{
	return g_ImportAddresses[index];
}

__attribute__((annotate("calls-imports")))
bool CallImportFunction()
{
	typedef enum _SYSTEM_INFORMATION_CLASS
	{
		SystemCodeIntegrity = 103
	} SYSTEM_INFORMATION_CLASS;

	typedef NTSTATUS(NTAPI* NtQuerySystemInformationFunc)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

	typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION
	{
		ULONG Length;
		ULONG CodeIntegrityOptions;
	} SYSTEM_CODEINTEGRITY_INFORMATION;

	auto ntQuerySystemInformation = reinterpret_cast<NtQuerySystemInformationFunc>(GetImportAddress(1));

	SYSTEM_CODEINTEGRITY_INFORMATION sci = { sizeof(sci), 0 };

	if (!NT_SUCCESS(ntQuerySystemInformation(SystemCodeIntegrity, &sci, sizeof(sci), nullptr)))
		return false;

	printf("Test mode enabled: %d\n", static_cast<int>(sci.CodeIntegrityOptions & 0x02));
	return true;
}

int main(void)
{
	if (!GetImportAddresses())
	{
		printf("Failed to fetch imports!\n");
		return -1;
	}

	CallImportFunction();

	return 0;
}