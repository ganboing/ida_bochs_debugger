	.686P
	.model	flat

PUBLIC	__callui_mod
PUBLIC	_qmakepath_mod
PUBLIC	_GetTF
PUBLIC	_SetTF
PUBLIC	_EndCatching

EXTERN	__callui_pre:PROC
EXTERN	__callui_post:PROC
EXTERN	_qmakepath_pre:PROC
EXTERN	_qmakepath_post:PROC
EXTERN	_GetLocalStorRestoreTF@0:PROC
EXTERN	_SetLocalStorResetTF@4:PROC
EXTERN	__imp__callui:DWORD
EXTERN	__imp__qmakepath:DWORD

_TEXT	SEGMENT

__callui_mod PROC
	;INT 3
	call _SetLocalStorResetTF@4
	call __callui_pre
	mov eax, DWORD PTR __imp__callui
	call DWORD PTR [eax]
	push eax
	call __callui_post
	call _GetLocalStorRestoreTF@0
	xchg DWORD PTR [esp], eax
	ret
__callui_mod ENDP

_qmakepath_mod PROC
	call _SetLocalStorResetTF@4
	call _qmakepath_pre
	call DWORD PTR __imp__qmakepath
	push eax
	call _qmakepath_post
	call _GetLocalStorRestoreTF@0
	xchg DWORD PTR [esp], eax
	ret
_qmakepath_mod ENDP

_GetTF PROC
	xor eax, eax
	pushfd
	btr DWORD PTR [esp], 8
	setc al
	add esp, 4
	ret
_GetTF ENDP

_SetTF PROC
	pushfd
	bts DWORD PTR [esp], 8
	popfd
	ret
_SetTF ENDP

_EndCatching PROC
	ret
_EndCatching ENDP

_TEXT	ENDS
END