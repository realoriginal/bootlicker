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
 * Searches for an export in a PE.
 *
!*/
D_SEC( H ) PVOID PeGetFuncEat( _In_ PVOID ImageBase, _In_ UINT32 ExportHash );
