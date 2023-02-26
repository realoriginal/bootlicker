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

/* Gets a pointer to the function or string via its relative offset to GetIp() */
#define G_PTR( x )	( ULONG_PTR )( GetIp( ) - ( ( ULONG_PTR ) & GetIp - ( ULONG_PTR ) x ) )

/* Cast as a function or variable in a specific section */
#define D_SEC( x )	__attribute__(( section( ".text$" #x ) ))

/* CAst as a pointer with the specified typedef */
#define D_API( x )	__typeof__( x ) * x

/* Cast as a pointer-wide variable */
#define U_PTR( x )	( ( ULONG_PTR ) x )

/* Cast as a pointer */
#define C_PTR( x )	( ( PVOID ) x )
