/** @file

  Copyright (c) 2025, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SMM_PROFILE_TEST_H__
#define __SMM_PROFILE_TEST_H__

#include <PiDxe.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiLib.h>
#include <Library/DevicePathLib.h>
#include <Library/DxeServicesLib.h>
#include <Library/UefiHiiServicesLib.h>
#include <Library/HiiLib.h>
#include <Library/ShellLib.h>
#include <Library/HobLib.h>
#include <Register/Intel/Cpuid.h>

#include <Protocol/MmCommunication.h>
#include <Protocol/LoadedImage.h>

#include <Guid/MmProfileData.h>
#include <Guid/SmmProfileTestHob.h>
#include <Guid/PiSmmCommunicationRegionTable.h>

#define SMM_PROFILE_NAME  L"SmmProfileData"
#define SMM_PROFILE_GUID  {0xD88F894B, 0x9287, 0x4706, { 0x8B, 0x28, 0xF7, 0x16, 0xAE, 0x4D, 0x35, 0xC7 }}

typedef struct {
  UINT64    HeaderSize;
  UINT64    MaxDataEntries;
  UINT64    MaxDataSize;
  UINT64    CurDataEntries;
  UINT64    CurDataSize;
  UINT64    TsegStart;
  UINT64    TsegSize;
  UINT64    NumSmis;
  UINT64    NumCpus;
} SMM_PROFILE_HEADER;

typedef struct {
  UINT64    SmiNum;
  UINT64    CpuNum;
  UINT64    ApicId;
  UINT64    ErrorCode;
  UINT64    Instruction;
  UINT64    Address;
  UINT64    SmiCmd;
} SMM_PROFILE_ENTRY;

#endif
