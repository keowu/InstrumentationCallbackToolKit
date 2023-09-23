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
#include "Defs.hh"

extern "C" ULONG_PTR CheckProcessContainerInstrumentation( _In_ ULONG_PTR pPEPROCESS );

namespace NirvanaHeuristics {

	auto DetectNirvanedProcess(

		void

	) -> NTSTATUS;

};