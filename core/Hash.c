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
 * Returns a DJB2 hash representation of an input buffer
 * of the specified length. If no length is provided, it
 * assumes it is a NULL terminated string.
 *
!*/
D_SEC( H ) UINT32 HashString( _In_ PVOID Buffer, _In_ UINT32 Length )
{
	UINT8	Val = 0;
	UINT32	Djb = 0;
	PUINT8	Buf = NULL;

	Djb = 5381;
	Buf = C_PTR( Buffer );

	while ( TRUE ) {
		/* Get the current character */
		Val = * Buf;

		if ( ! Length ) {
			/* NULL Terminated */
			if ( ! * Buf ) {
				/* Abort! */
				break;
			};
		} else 
		{
			/* Is the current position exceed the length of the buffer? */
			if ( ( UINT32 )( Buf - ( PUINT8 ) Buffer ) >= Length ) {
				break;
			};
			/* NULL Terminated */
			if ( ! * Buf ) {
				/* Increment and move onto the next */
				++Buf; continue;
			};
		};
		/* Lowercase */
		if ( Val >= 'a' ) {
			/* Decrement to uppercase */
			Val -= 0x20;
		};

		/* Hash the current character */
		Djb = ( ( Djb << 5 ) + Djb ) + Val; ++Buf;
	};

	/* Return the hash */
	return Djb;
};
