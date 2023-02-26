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

/*!
 *
 * Purpose:
 *
 * Searches for an export in a PE.
 *
!*/
D_SEC( H ) PVOID PeGetFuncEat( _In_ PVOID ImageBase, _In_ UINT32 ExportHash )
{
	PUINT16			Aoo = NULL;
	PUINT32			Aon = NULL;
	PUINT32			Aof = NULL;
	PIMAGE_DOS_HEADER	Dos = NULL;
	PIMAGE_NT_HEADERS	Nth = NULL;
	PIMAGE_DATA_DIRECTORY	Dir = NULL;
	PIMAGE_EXPORT_DIRECTORY	Exp = NULL;

	/* Get address to headers */
	Dos = C_PTR( ImageBase );
	Nth = C_PTR( U_PTR( Dos ) + Dos->e_lfanew );
	Dir = & Nth->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

	/* Does an export table exist? */
	if ( Dir->VirtualAddress ) {
		/* Get offsets to names, funcs, ordinals */
		Exp = C_PTR( U_PTR( Dos ) + Dir->VirtualAddress );
		Aon = C_PTR( U_PTR( Dos ) + Exp->AddressOfNames );
		Aof = C_PTR( U_PTR( Dos ) + Exp->AddressOfFunctions );
		Aoo = C_PTR( U_PTR( Dos ) + Exp->AddressOfNameOrdinals );

		/* Enumerate all the exports */
		for ( INT Idx = 0 ; Idx < Exp->NumberOfNames ; ++Idx ) {
			/* Is this our export? */
			if ( HashString( C_PTR( U_PTR( Dos ) + Aon[ Idx ] ), 0 ) == ExportHash ) {
				/* Return pointer */
				return C_PTR( U_PTR( Dos ) + Aof[ Aoo[ Idx ] ] );
			};
		};
	};
	/* Abort! */
	return NULL;
};
