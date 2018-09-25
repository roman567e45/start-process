//win32:LIBS += -lkernel32

#include <windows.h>

static inline void FBytesZero(void *const pDst, const uint iSize)
{
    BYTE *pbtDst = static_cast<BYTE*>(pDst);
    const BYTE *const pbtEnd = pbtDst + iSize;
    while (pbtDst < pbtEnd)
        *pbtDst++ = '\0';
}

static void FRunKernel32(const QString &strFilePath)
{
    PROCESS_INFORMATION pi;
    STARTUPINFO si;
    FBytesZero(&si, sizeof(STARTUPINFOW));
    si.cb = sizeof(STARTUPINFO);
    if (CreateProcessW(nullptr, const_cast<wchar_t*>(static_cast<const wchar_t*>(static_cast<const void*>(strFilePath.utf16()))), nullptr, nullptr, FALSE, CREATE_UNICODE_ENVIRONMENT, nullptr, nullptr, &si, &pi))
    {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
}