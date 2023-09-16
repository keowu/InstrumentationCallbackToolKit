; _   __ _____ _____  _    _ _   _
;| | / /|  ___|  _  || |  | | | | |
;| |/ / | |__ | | | || |  | | | | |
;|    \ |  __|| | | || |/\| | | | |
;| |\  \| |___\ \_/ /\  /\  / |_| |
;\_| \_/\____/ \___/  \/  \/ \___/
;                            2023
;Copyright (c) Fluxuss Cyber Tech Desenvolvimento de Software, SLU (FLUXUSS)
;Copyright (c) Fluxuss Software Security, LLC

extrn RtlCaptureContext: proc
extrn NtCurrentTeb: proc
extrn RtlRestoreContext: proc
extern StuffProc: proc

includelib Dbghelp.lib

.code

InstrumentationRoutine proc
	; ps: RCX armazena o ponteiro de nossa CONTEXT

	; RIP = TEB->InstrumentationCallbackPreviousPc
	mov r14, qword ptr gs:[02D8h]
	mov qword ptr[rcx + 0F8h], r14

	; RSP = TEB->InstrumentationCallbackPreviousSp
	mov r14, qword ptr gs:[02E0h]
	mov qword ptr[rcx + 98h], r14

	; RCX = R10
	mov r14, qword ptr [rcx + 0C8h]
	mov qword ptr[rcx + 80h], r14

	push rcx ; Armazenamos RCX na stack

	cmp byte ptr gs:[1B8h], 0
	jnz teb_bug_check

	mov byte ptr gs:[1B8h], 1 ; TEB->InstrumentationCallbackDisabled = TRUE

	mov rcx, qword ptr gs:[02D8h] 

	call StuffProc

	mov byte ptr gs:[1B8h], 0 ; TEB->InstrumentationCallbackDisabled = FALSE

	teb_bug_check:

		xor rdx, rdx
		pop rcx ; Retornamos RCX para restaurar o contexto
		
		call RtlRestoreContext ; Restauramos o contexto da thread atual

	ret

InstrumentationRoutine endp


InstrumentationCallbackProxy proc
	
	; TEB->InstrumentationCallbackPreviousSp = rsp
	mov     gs:[2e0h], rsp            
	; TEB->InstrumentationCallbackPreviousPc = r10
	mov     gs:[2d8h], r10            
	;r10 = rcx para salvarmos o valor original dele
	mov     r10, rcx

	; Alocando espaço na stack para caber nossa struct CONTEXT
	; Como aqui nesse caso essa rotina sofre com muita recursão, e não temos um controle de
	; variáveis de bugcheck podemos facilmente corromper o acesso ou valores de variaveis da seção .data
	; por esse único motivo usamos valores stack based aqui
	sub     rsp, 4d0h
	
	; Precisamos alinhar a stack em 16 bytes, antes de fazermos uma chamada, porque vamos usa-la para armazenar valores
	and     rsp, -10h

	; RtlCaptureContext(rcx)
	mov     rcx, rsp
	call RtlCaptureContext   

	; InstrumentationRoutine(rcx)
	call InstrumentationRoutine

InstrumentationCallbackProxy endp

end