/*
 _   __ _____ _____  _    _ _   _
| | / /|  ___|  _  || |  | | | | |
| |/ / | |__ | | | || |  | | | | |
|    \ |  __|| | | || |/\| | | | |
| |\  \| |___\ \_/ /\  /\  / |_| |
\_| \_/\____/ \___/  \/  \/ \___/
                            2023
Copyright (c) Fluxuss Cyber Tech Desenvolvimento de Software, SLU (FLUXUSS)
Copyright (c) Fluxuss Software Security, LLC
*/
#ifndef PCH_H
#define PCH_H

#include "framework.h"

#include <Windows.h>
#include <winternl.h>

#include <DbgHelp.h>
#include <stdio.h>

#pragma comment(lib, "ntdll.lib") 
#pragma comment(lib,"Dbghelp.lib")

#include <iostream>


#define PROCESS_INFO_CLASS_INSTRUMENTATION 40

typedef NTSTATUS ( NTAPI* pNtSetInformationProcess ) (

    HANDLE ProcessHandle,
    PROCESS_INFORMATION_CLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength
 
);

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION {

    ULONG Version;
    ULONG Reserved;
    PVOID Callback;

} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, * PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

#endif //PCH_H
