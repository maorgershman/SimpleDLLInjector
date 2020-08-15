#pragma once

#include <Windows.h>

#ifdef __cplusplus
extern "C"
{
#endif

void inject(DWORD dwPID, LPCSTR cstrDLLFilePath);

#ifdef __cplusplus
}
#endif