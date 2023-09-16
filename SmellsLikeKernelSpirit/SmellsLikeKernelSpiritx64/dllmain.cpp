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
#include "pch.h"

extern "C" VOID InstrumentationCallbackProxy( 
    
    VOID 

);

extern "C" VOID StuffProc(
    
    _In_ uintptr_t pRIP

);

auto NtSetInformationProcess = reinterpret_cast<pNtSetInformationProcess>( 
    
    ::GetProcAddress( 
 
        _In_ ::GetModuleHandleA(
            
            _In_ "ntdll.dll"
        
        ),
        _In_ "NtSetInformationProcess"
 
    )

);


VOID StuffProc( 
    
    _In_ uintptr_t pRIP

) {

    BYTE SymbolBuffer[ sizeof( SYMBOL_INFO ) + MAX_SYM_NAME ] { 0 };

    PSYMBOL_INFO SymbolInfo = reinterpret_cast< PSYMBOL_INFO >( SymbolBuffer );

    SymbolInfo->SizeOfStruct = sizeof( SYMBOL_INFO );

    SymbolInfo->MaxNameLen = MAX_SYM_NAME;

    if ( ::SymFromAddr(
        
        _In_ reinterpret_cast< HANDLE >( -1 ),
        _In_ pRIP,
        _Out_opt_ NULL,
        _Inout_ SymbolInfo
    
    ) ) std::printf(
        
        _In_ "Get: %s\n",
        _In_ SymbolInfo->Name
    
    );
        
}

auto BeginNirvana(

) -> void {

    #pragma warning(disable : 4996)
    ::AllocConsole( );

    ::freopen( 
        
        _In_ "CONOUT$",
        _In_ "w",
        _In_ stdout
    
    );

    ::SymSetOptions(
        
        _In_ SYMOPT_UNDNAME
    
    );

    ::SymInitialize(
        
        _In_ reinterpret_cast< HANDLE >( -1 ),
        _In_opt_ NULL,
        _In_ TRUE
    
    );

    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION niInstrumentationCallBack;


    niInstrumentationCallBack.Version = 0;
    niInstrumentationCallBack.Reserved = 0;
    niInstrumentationCallBack.Callback = ::InstrumentationCallbackProxy;

    NtSetInformationProcess(
    
        _In_ reinterpret_cast< HANDLE >( -1 ),
        _In_ static_cast< PROCESS_INFORMATION_CLASS >( PROCESS_INFO_CLASS_INSTRUMENTATION ),
        _In_ &niInstrumentationCallBack,
        _In_ sizeof( niInstrumentationCallBack )
    
    );

    std::printf(
        
        _In_ "Nirvana begins !\n"
    
    );
}


BOOL APIENTRY DllMain(
    
    _In_ HMODULE hModule,
    _In_ DWORD  ul_reason_for_call,
    _In_ LPVOID lpReserved

) {
    switch ( ul_reason_for_call ) {

    case DLL_PROCESS_ATTACH: {
        
        ::BeginNirvana( );

    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
    
        break;
    }

    return TRUE;
}

