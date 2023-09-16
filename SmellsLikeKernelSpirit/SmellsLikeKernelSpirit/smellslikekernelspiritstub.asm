; _   __ _____ _____  _    _ _   _
;| | / /|  ___|  _  || |  | | | | |
;| |/ / | |__ | | | || |  | | | | |
;|    \ |  __|| | | || |/\| | | | |
;| |\  \| |___\ \_/ /\  /\  / |_| |
;\_| \_/\____/ \___/  \/  \/ \___/
;                            2023
;Copyright (c) Fluxuss Cyber Tech Desenvolvimento de Software, SLU (FLUXUSS)
;Copyright (c) Fluxuss Software Security, LLC

.model flat

assume fs:nothing

extern _StuffProc: proc

.code

_InstrumentationCallbackProxy proc

    mov fs:1b0h, ecx  ; TEB->InstrumentationCallbackPreviousPc             
    mov fs:1b4h, esp  ; TEB->InstrumentationCallbackPreviousSp

    cmp eax, 0 ; A NTSTATUS de retorno da syscall executada é um STATUS_SUCCES ? se não for ignore(porque não há o que capturar por aqui)
    jnz go_out
    
    cmp byte ptr [fs:01b8h], 0 ; TEB->InstrumentationCallbackDisabled = FALSE 
    jnz go_out

    mov byte ptr [fs:01b8h], 1 ; TEB->InstrumentationCallbackDisabled = TRUE

    ; EAX carrega a flag de NTSTATUS, você pode fazer o que quiser com ela!
    push ecx ; ECX de onde a syscall for invocada
    call _StuffProc

    mov byte ptr [fs:01b8h], 0 ; TEB->InstrumentationCallbackDisabled = FALSE

go_out:

    mov     esp, fs:1b4h ; TEB->InstrumentationCallbackPreviousSp
    mov     ecx, fs:1b0h ; TEB->InstrumentationCallbackPreviousPc        

    jmp     ecx ; Salta para continuar a execução do contexto da thread atual

_InstrumentationCallbackProxy endp

assume fs:error
end