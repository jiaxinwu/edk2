/** @file

  Copyright (c) 2025, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _SMM_PROFILE_TEST_STANDALONEMM_H_
#define _SMM_PROFILE_TEST_STANDALONEMM_H_

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/IoLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/PeCoffGetEntryPointLib.h>
#include <Library/HobLib.h>

#include <Protocol/LoadedImage.h>
#include <Protocol/FirmwareVolume2.h>

#include <Guid/SmmProfileTestHob.h>

/**
  Read 64 bits from the Memory space.

  @param[in] Address - Memory address.
**/
UINT64
EFIAPI
AsmReadMem64 (
  IN  UINT64  Address
  );

#endif
