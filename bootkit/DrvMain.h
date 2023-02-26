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
 * Copies over a larger kernel shellcode and injects
 * it into the host memory.
 *
!*/
D_SEC( G ) NTSTATUS NTAPI DrvMain( _In_ PVOID DriverObject, _In_ PVOID RegistryPath );
