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
#include <ntifs.h>
#include "NirvanaHeuristics.hh"

extern "C" {


	NTSTATUS DriverEntry(

		_In_ PDRIVER_OBJECT pDriverObject,
		_In_ PUNICODE_STRING pRegistryPath

	);

	VOID UnloadDriver(

		_In_ PDRIVER_OBJECT pDriverObject

	);


}

