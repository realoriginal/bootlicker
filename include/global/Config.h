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

/* Configuration file */
typedef struct __attribute__(( packed, scalar_storage_order( "big-endian" ) ))
{
	UINT32		AddressOfEntrypoint;
	UINT32		AddressOfNewExeHeader;
} CONFIG, *PCONFIG ;
