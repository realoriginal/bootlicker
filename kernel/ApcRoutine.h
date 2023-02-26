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
 * Inserts a APC callback into the usermode process.
 *
!*/
D_SEC( D ) VOID NTAPI ApcNormalRoutine( _In_ PVOID NormalContext, _In_ PVOID SystemArgument1, _In_ PVOID SystemArgument2 );

/*!
 *
 * Purpose:
 *
 * Empty kernel APC routine thats executed for user
 * and kernel mode.
 *
!*/
D_SEC( D ) VOID NTAPI ApcKernelRoutine( _In_ PRKAPC Apc, _In_ PVOID* NormalRoutine, _In_ PVOID* NormalContext, _In_ PVOID* SystemArgument1, _In_ PVOID* SystemArgument2 );
