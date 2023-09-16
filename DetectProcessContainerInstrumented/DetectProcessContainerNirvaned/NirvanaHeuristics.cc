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
#include "NirvanaHeuristics.hh"

auto NirvanaHeuristics::DetectNirvanedProcess(

    void

) -> NTSTATUS {

    ULONG ulReturnLength{ 0 };

    auto status = ::ZwQuerySystemInformation(

        _In_ SystemProcessInformation,
        _Inout_ NULL,
        _In_ 0,
        _Out_opt_ &ulReturnLength

    );

    if ( status != STATUS_INFO_LENGTH_MISMATCH ) return STATUS_UNSUCCESSFUL;

    auto pSystemProcess = reinterpret_cast< SYSTEM_PROCESSES* >( ::ExAllocatePool2(

        _In_ POOL_FLAG_NON_PAGED,
        _In_ 2 * ulReturnLength,
        _In_ 'DRM'

    ) );

    if ( !pSystemProcess ) return STATUS_NO_MEMORY;

    status = ::ZwQuerySystemInformation(

        _In_ SystemProcessInformation,
        _Inout_ pSystemProcess,
        _In_ 2 * ulReturnLength,
        _Out_opt_ NULL

    );

    if ( !NT_SUCCESS( status ) ) return STATUS_UNSUCCESSFUL;

    SYSTEM_PROCESSES* i = pSystemProcess;

    do {

        PEPROCESS peProcess;

        status = ::PsLookupProcessByProcessId(
            
            _In_ reinterpret_cast< HANDLE >( i->ProcessId ),
            _Outptr_ &peProcess
        
        );

        if ( NT_SUCCESS( status ) ) {

            KAPC_STATE kApcState;

            auto ppeProcess = reinterpret_cast< ULONG_PTR >( peProcess );

            ppeProcess += 0x3d8;

            ::KeStackAttachProcess(
                
                _Inout_ peProcess,
                _Out_ &kApcState
            
            );

            auto phyAddress = ::MmGetPhysicalAddress(
                
                _In_ *reinterpret_cast< PVOID* >( ppeProcess )
            
            );

            if ( *reinterpret_cast< ULONG_PTR* >( ppeProcess ) )

                ::DbgPrintEx(

                    _In_ 0,
                    _In_ 0,
                    _In_ "Detected a Nirvaned Process: %ls\nVirtual Address: %p\nPhysical Address: %p",
                    _In_ i->ProcessName.Buffer,
                    _In_ *reinterpret_cast< ULONG_PTR* >( ppeProcess ),
                    _In_ phyAddress.QuadPart

                );

            ::KeUnstackDetachProcess(

                _In_ &kApcState

            );

        }

        i = reinterpret_cast< SYSTEM_PROCESSES* >( reinterpret_cast< ULONG_PTR >( i ) + i->NextEntryDelta );

    } while ( i->NextEntryDelta );

     ::ExFreePoolWithTag(
         
         _In_ pSystemProcess,
         _In_ 'DRM'
     
     );

    return STATUS_SUCCESS;
}