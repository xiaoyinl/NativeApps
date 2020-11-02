// This program was originally written by Pavel Yosifovich (https://github.com/zodiacon).
// The original file can be found at https://github.com/zodiacon/NativeApps/blob/master/nativerun/nativerun.cpp

// nativerun.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <string>

#pragma comment(lib, "ntdll")

using std::wcout;
using std::wstring;

const wchar_t programPurpose[] = L"This program launches a Windows native application, a DLL, or a kernel driver as a user-mode exe.\n";
const wchar_t programUsage[] = L"Usage:\n  nativerun.exe (use this program interactively)\n  nativerun.exe <executable> [params]\n  nativerun.exe /?  (show the help message)\n";
typedef struct _RTL_USER_PROCESS_INFORMATION {
    ULONG Length;
    HANDLE Process;
    HANDLE Thread;
    CLIENT_ID ClientId;
    //SECTION_IMAGE_INFORMATION ImageInformation;
    BYTE reserved[64];
} RTL_USER_PROCESS_INFORMATION, * PRTL_USER_PROCESS_INFORMATION;

extern "C" {
    NTSTATUS NTAPI NtCreateProcess(
        _Out_ PHANDLE ProcessHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_ HANDLE ParentProcess,
        _In_ BOOLEAN InheritObjectTable,
        _In_opt_ HANDLE SectionHandle,
        _In_opt_ HANDLE DebugPort,
        _In_opt_ HANDLE ExceptionPort
    );
    NTSTATUS NTAPI RtlCreateUserProcess(
        __in PUNICODE_STRING NtImagePathName,
        __in ULONG Attributes,
        __in PVOID ProcessParameters,
        __in_opt PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
        __in_opt PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
        __in_opt HANDLE ParentProcess,
        __in BOOLEAN InheritHandles,
        __in_opt HANDLE DebugPort,
        __in_opt HANDLE TokenHandle,
        __out PRTL_USER_PROCESS_INFORMATION ProcessInformation
    );

    NTSTATUS NTAPI RtlCreateProcessParameters(
        __deref_out PVOID* pProcessParameters,
        __in PUNICODE_STRING ImagePathName,
        __in_opt PUNICODE_STRING DllPath,
        __in_opt PUNICODE_STRING CurrentDirectory,
        __in_opt PUNICODE_STRING CommandLine,
        __in_opt PVOID Environment,
        __in_opt PUNICODE_STRING WindowTitle,
        __in_opt PUNICODE_STRING DesktopInfo,
        __in_opt PUNICODE_STRING ShellInfo,
        __in_opt PUNICODE_STRING RuntimeData
    );
}
int Error(NTSTATUS status)
{
    if (status == STATUS_OBJECT_NAME_NOT_FOUND)
    {
        std::wcerr << L"Error: the file doesn't exist.\n";
    }
    else if (status == STATUS_INVALID_IMAGE_NOT_MZ)
    {
        std::wcerr << L"Error: the file is not a valid Windows PE executable file.\n";
    }
    else
    {
        std::wcerr << L"Error: status 0x" << std::hex << status << L"\n";
    }
    return 1;
}
void toNativePath(_Inout_ wstring& winPath)
{
    if (winPath.find(L"\\Device\\") == 0 || winPath.find(L"\\??\\") == 0)
    {
        // already a valid native-mode file path
        return;
    }
    wchar_t buf[MAX_PATH]{};
    DWORD ret = GetFullPathNameW(winPath.c_str(), MAX_PATH, buf, nullptr);
    if (ret == 0 || ret >= MAX_PATH - 1)
    {
        // If GetFullPathNameW returns 0, an error occurs.
        // If it returns a size larger than or equal to MAX_PATH - 1, the buffer is too small. (This shouldn't happen, so treat it as an error)
        winPath = L"";
    }
    else
    {
        wstring ntPath(L"\\??\\");
        ntPath = ntPath + buf;
        winPath = ntPath;
    }
}
int wmain(int argc, const wchar_t* argv[])
{
    wstring exeToStart;
    wstring paramList;
    bool suspendInitialThread = false;
    if (argc == 1)
    {
        wcout << programPurpose << L"\n";
        wcout << L"Path of the file to launch: ";
        std::getline(std::wcin, exeToStart);
        wcout << L"Parameters: ";
        std::getline(std::wcin, paramList);

        wcout << L"Suspend the initial thread? (y/N): ";
        wstring doSuspend;
        std::getline(std::wcin, doSuspend);
        if (doSuspend == L"Y" || doSuspend == L"y")
            suspendInitialThread = true;
    }
    else if (argc == 2 && ( wcscmp(argv[1], L"/?") == 0 || wcscmp(argv[1], L"--help") == 0))
    {
        wcout << programPurpose << L"\n";
        wcout << programUsage << L"\n";
        return 0;
    }
    else if (argc == 2)
    {
        exeToStart = argv[1];
    }
    else
    {
        exeToStart = argv[1];
        paramList = argv[2];
    }
    toNativePath(exeToStart);
    if (exeToStart.size() == 0)
    {
        std::wcerr << L"You entered an invalid file path.\n";
        return 1;
    }
    wcout << L"Launching file " << exeToStart << L"\n";
    UNICODE_STRING name{};
    RtlInitUnicodeString(&name, exeToStart.c_str());

    UNICODE_STRING params{};
    if (paramList.size() != 0)
        RtlInitUnicodeString(&params, paramList.c_str());
    else
        RtlInitUnicodeString(&params, exeToStart.c_str());

    RTL_USER_PROCESS_INFORMATION info{};
    PVOID processParams = nullptr;
    auto status = RtlCreateProcessParameters(&processParams, &name, nullptr, nullptr, &params,
        nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!NT_SUCCESS(status))
        return Error(status);

    status = RtlCreateUserProcess(&name, 0, processParams, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &info);
    if (!NT_SUCCESS(status))
        return Error(status);

    wcout << L"Process " << HandleToULong(info.ClientId.UniqueProcess) << L" created!\n";

    if (!suspendInitialThread)
        ResumeThread(info.Thread);

    return 0;
}
