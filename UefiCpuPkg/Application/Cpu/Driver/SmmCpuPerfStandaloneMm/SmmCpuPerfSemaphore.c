/** @file

  Copyright (c) 2025, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SmmCpuPerfStandaloneMm.h"

/**
  Performs an atomic operation to increase CPU count.
  The operation must be performed using MP safe mechanisms.

  @param      Count      IN:  32-bit unsigned integer
                         OUT: original integer + 1
  @return     Original integer + 1

**/
INT32
CpuCountIncrement (
  IN OUT  volatile UINT32  *Count
  )
{
  return (INT32)InterlockedIncrement (Count);
}

/**
  Used for BSP to wait all APs.

  @param   NumberOfAPs      AP number

**/
VOID
WaitForAllAPs (
  IN      UINTN  NumberOfAPs
  )
{
  while (NumberOfAPs != *mSemaphoreCpu[mBspIndex].Run) {
    CpuPause ();
  }

  *mSemaphoreCpu[mBspIndex].Run = 0;
}

/**
  Used for BSP to release all APs.

**/
VOID
ReleaseAllAPs (
  VOID
  )
{
  UINTN  Index;

  for (Index = 0; Index < gMmst->NumberOfCpus; Index++) {
    //
    // Must exclude mBspIndex
    //
    if (Index != mBspIndex) {
      ASSERT (*mSemaphoreCpu[Index].Run == 0);
      *mSemaphoreCpu[Index].Run = 1;
    }
  }
}

/**
  Used for AP to wait BSP.

  @param      ApSem      IN:  32-bit unsigned integer
                         OUT: original integer 0
**/
VOID
WaitForBsp  (
  IN OUT  volatile UINT32 *ApSem
  )
{
  while (*ApSem == 0) {
    CpuPause ();
  }

  *ApSem = 0;
}

/**
  Used for AP to release BSP.

  @param      BspSem     IN:  32-bit unsigned integer
                         OUT: original integer + 1
**/
VOID
ReleaseBsp   (
  IN OUT  volatile UINT32  *BspSem
  )
{
  InterlockedIncrement (BspSem);
}
