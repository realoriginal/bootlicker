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

typedef struct __attribute__(( packed ))
{
	PVOID	KernelBase;
	ULONG	InitialRun;
} KMTBL, *PKMTBL ;
