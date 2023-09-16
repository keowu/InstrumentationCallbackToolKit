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
#include "MainDriver.hh"


VOID UnloadDriver(

	_In_ PDRIVER_OBJECT pDriverObject

) {

    DbgPrintEx(

        _In_ 0,
        _In_ 0,
        _In_ "GoodBye, Driver Unload !!"

    );

    UNREFERENCED_PARAMETER(pDriverObject);

}


NTSTATUS DriverEntry(

	_In_ PDRIVER_OBJECT pDriverObject,
	_In_ PUNICODE_STRING pRegistryPath

) {

    pDriverObject->DriverUnload = UnloadDriver;

    UNREFERENCED_PARAMETER( pDriverObject);

    UNREFERENCED_PARAMETER( pRegistryPath );

    DbgPrintEx(

        _In_ 0,
        _In_ 0,
        _In_ "Hello World !!"

    );

    NTSTATUS status = ::NirvanaHeuristics::DetectNirvanedProcess( );

    DbgPrintEx(

        _In_ 0,
        _In_ 0,
        _In_"NirvanaHeuristics::DetectNirvanedProcess( ) Status: %X",
        _In_ status

    );

    return STATUS_SUCCESS;
}