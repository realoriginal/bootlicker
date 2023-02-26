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
 * Inserts a hook into OslArchTransferToKernel.
 *
!*/
D_SEC( B ) EFI_STATUS EFIAPI ExitBootServicesHook( EFI_HANDLE ImageHandle, UINTN Key );
