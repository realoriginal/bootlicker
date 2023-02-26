/*!
 *
 * BOOTLICKER
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#pragma once

/*!
 *
 * Purpose:
 *
 * Returns a DJB2 hash representation of an input buffer
 * of the specified length. If no length is provided, it
 * assumes it is a NULL terminated string.
 *
!*/
D_SEC( H ) UINT32 HashString( _In_ PVOID Buffer, _In_ UINT32 Length );
