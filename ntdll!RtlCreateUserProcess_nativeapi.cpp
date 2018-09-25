//win32:LIBS += -lntdll

#include <winternl.h>

#ifndef RTL_MAX_DRIVE_LETTERS
#define RTL_MAX_DRIVE_LETTERS 32
#endif

#ifndef RTL_USER_PROCESS_PARAMETERS_NORMALIZED
#define RTL_USER_PROCESS_PARAMETERS_NORMALIZED 0x01
#endif

struct RTL_USER_PROCESS_INFORMATION
{
    ULONG Length;
    HANDLE Process;
    HANDLE Thread;
    CLIENT_ID ClientId;
    struct SECTION_IMAGE_INFORMATION
    {
        PVOID TransferAddress;
        ULONG ZeroBits;
        SIZE_T MaximumStackSize;
        SIZE_T CommittedStackSize;
        ULONG SubSystemType;
        ULONG SubSystemVersion;
        ULONG OperatingSystemVersion;
        USHORT ImageCharacteristics;
        USHORT DllCharacteristics;
        USHORT Machine;
        BOOLEAN ImageContainsCode;
        UCHAR ImageFlags;
        ULONG LoaderFlags;
        ULONG ImageFileSize;
        ULONG CheckSum;
    } ImageInformation;
};

struct EX_RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;
    struct CURDIR
    {
        UNICODE_STRING DosPath;
        HANDLE Handle;
    } CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;
    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    struct RTL_DRIVE_LETTER_CURDIR
    {
        USHORT Flags;
        USHORT Length;
        ULONG TimeStamp;
        UNICODE_STRING DosPath;
    } CurrentDirectories[RTL_MAX_DRIVE_LETTERS];
    ULONG_PTR EnvironmentSize;
    ULONG_PTR EnvironmentVersion;
    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;
};

struct EX_TEB
{
    NT_TIB NtTib;
    PVOID EnvironmentPointer;
    CLIENT_ID ClientId;
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
    struct EX_PEB
    {
        BOOLEAN InheritedAddressSpace;
        BOOLEAN ReadImageFileExecOptions;
        BOOLEAN BeingDebugged;
        BOOLEAN BitField;
        HANDLE Mutant;
        HINSTANCE ImageBaseAddress;
        PVOID *Ldr;
        EX_RTL_USER_PROCESS_PARAMETERS *ProcessParameters;
        //...
        EX_PEB() = delete;
    } *ProcessEnvironmentBlock;
    //...
    EX_TEB() = delete;
};

//-------------------------------------------------------------------------------------------------
extern "C"
{
__declspec(dllimport) NTSTATUS NTAPI NtClose(HANDLE Handle);
__declspec(dllimport) NTSTATUS NTAPI NtResumeThread(HANDLE ThreadHandle, PULONG SuspendCount);
__declspec(dllimport) NTSTATUS NTAPI RtlCreateUserProcess(PUNICODE_STRING ImageFileName, ULONG Attributes, EX_RTL_USER_PROCESS_PARAMETERS *ProcessParameters, PSECURITY_DESCRIPTOR ProcessSecurityDescriptor, PSECURITY_DESCRIPTOR ThreadSecurityDescriptor, HANDLE ParentProcess, BOOLEAN InheritHandles, HANDLE DebugPort, HANDLE ExceptionPort, RTL_USER_PROCESS_INFORMATION *ProcessInfo);
}

static inline wchar_t * FWStrCopyEx(wchar_t *pDst, const wchar_t *pSrc)
{
    while ((*pDst = *pSrc))
        ++pDst, ++pSrc;
    return pDst;
}

static inline void FBytesZero(void *const pDst, const uint iSize)
{
    BYTE *pbtDst = static_cast<BYTE*>(pDst);
    const BYTE *const pbtEnd = pbtDst + iSize;
    while (pbtDst < pbtEnd)
        *pbtDst++ = '\0';
}

static void FRunNtdll(const QString &strFilePath)
{
    if (strFilePath.size() < MAX_PATH)
    {
        wchar_t wImgFileName[4 + (MAX_PATH - 1)];
        wchar_t wCmdLine[1 + (MAX_PATH - 1) + 1];
        const wchar_t *const pwStrFilePath = static_cast<const wchar_t*>(static_cast<const void*>(strFilePath.utf16()));

        wchar_t *pwImgFileName = wImgFileName;
        *pwImgFileName++ = '\\';
        *pwImgFileName++ = '?';
        *pwImgFileName++ = '?';
        *pwImgFileName++ = '\\';
        const wchar_t *const pwImgFileNameEnd = FWStrCopyEx(pwImgFileName, pwStrFilePath);

        wchar_t *pwCmdLineEnd = wCmdLine;
        *pwCmdLineEnd++ = '"';
        pwCmdLineEnd = FWStrCopyEx(pwCmdLineEnd, pwStrFilePath);
        *pwCmdLineEnd++ = '"';

        UNICODE_STRING usImgFileName;
        usImgFileName.Buffer = wImgFileName;
        usImgFileName.MaximumLength = usImgFileName.Length = static_cast<USHORT>(static_cast<size_t>(pwImgFileNameEnd - wImgFileName)*sizeof(wchar_t));

        EX_RTL_USER_PROCESS_PARAMETERS procParamsExe;
        FBytesZero(&procParamsExe, sizeof(EX_RTL_USER_PROCESS_PARAMETERS));
        procParamsExe.Flags = RTL_USER_PROCESS_PARAMETERS_NORMALIZED;

        procParamsExe.ImagePathName.Buffer = pwImgFileName;
        procParamsExe.ImagePathName.MaximumLength = procParamsExe.ImagePathName.Length = static_cast<USHORT>(static_cast<size_t>(pwImgFileNameEnd - pwImgFileName)*sizeof(wchar_t));

        procParamsExe.CommandLine.Buffer = wCmdLine;
        procParamsExe.CommandLine.MaximumLength = procParamsExe.CommandLine.Length = (pwCmdLineEnd - wCmdLine)*sizeof(wchar_t);

        EX_RTL_USER_PROCESS_PARAMETERS *const pProcParamsParent = reinterpret_cast<const EX_TEB*>(
            #ifdef _WIN64
                    __readgsqword
            #else
                    __readfsdword
            #endif
                    (FIELD_OFFSET(NT_TIB, Self)))->ProcessEnvironmentBlock->ProcessParameters;

        const UNICODE_STRING *const pUsCurDirParent = &pProcParamsParent->CurrentDirectory.DosPath;
        procParamsExe.CurrentDirectory.DosPath.Buffer = pUsCurDirParent->Buffer;
        procParamsExe.CurrentDirectory.DosPath.MaximumLength = procParamsExe.CurrentDirectory.DosPath.Length = pUsCurDirParent->Length;

        procParamsExe.Environment = pProcParamsParent->Environment;
        procParamsExe.EnvironmentSize = pProcParamsParent->EnvironmentSize;

        RTL_USER_PROCESS_INFORMATION procInfo;
        if (NT_SUCCESS(RtlCreateUserProcess(&usImgFileName, 0, &procParamsExe, nullptr, nullptr, nullptr, FALSE, nullptr, nullptr, &procInfo)))
        {
            NtResumeThread(procInfo.Thread, nullptr);
            NtClose(procInfo.Thread);
            NtClose(procInfo.Process);
        }
    }
}
