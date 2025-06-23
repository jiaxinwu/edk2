/** @file

  Copyright (c) 2025, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SmmCpuPerfStandaloneMm.h"

LOCK_FUNCTION  mLockFunction[LockFuncMax] = {LockInc, LockXadd, LockCmpxchg};

/**
 BSP Lock Perf Check:

     Begin Ticks
  1. LockInc ()
     End Ticks

     Begin Ticks
  2. LockXadd ()
     End Ticks

     Begin Ticks
  3. LockCmpxchg ()
     End Ticks

  @param[out] SmmCpuBspLockData  Return BSP lock Perf Data.
  @param[in]  Round              Test round.

  @retval EFI_SUCCESS    Retrieved BSP lock Perf Data successfully.

**/
EFI_STATUS
SmmCpuBspLockPerf (
  OUT SMM_CPU_BSP_LOCK_DATA         *SmmCpuBspLockData,
  IN  UINTN                         Round
  )
{
  UINTN                                 LockFuncIndex;
  UINTN                                 RoundIndex;
  UINT64                                BeginTicks;
  UINT64                                EndTicks;
  UINT64                                TotalTicks;
  volatile UINT32                       *LockValue;

  //
  // Allocated to make sure the address is aligned within one exclusive cache line.
  //
  LockValue = (UINT32*) AllocatePages (EFI_SIZE_TO_PAGES (GetSpinLockProperties ()));
  DEBUG ((DEBUG_INFO, "[%a] - LockValue Address : 0x%08x\n", __FUNCTION__, (UINTN)LockValue));


  ASSERT (SmmCpuBspLockData != NULL);
  ZeroMem (SmmCpuBspLockData, sizeof (SMM_CPU_BSP_LOCK_DATA));

  //
  // Sub function test
  //
  for (LockFuncIndex = 0; LockFuncIndex < LockFuncMax; LockFuncIndex++) {
    TotalTicks = 0;

    //
    // Reset LockValue to 0 for each round test
    //
    *LockValue = 0;

    for (RoundIndex = 0; RoundIndex < Round; RoundIndex ++) {
      BeginTicks = GetPerformanceCounter ();
      mLockFunction[LockFuncIndex] (LockValue);
      EndTicks = GetPerformanceCounter ();

      TotalTicks += (EndTicks - BeginTicks);
    }

    //
    // Sanity check
    //
    if (LockFuncIndex == LockFuncLockInc) {
      ASSERT (*LockValue == Round);
    } else if (LockFuncIndex == LockFuncLockXadd) {
      ASSERT (*LockValue == Round);
    } else if (LockFuncIndex == LockFuncLockCmpxchg) {
      ASSERT (*LockValue == 0);
    } else {
      ASSERT (FALSE);
    }

    //
    // Update returned AvgTicks
    //
    SmmCpuBspLockData->AvgTicks[LockFuncIndex] = (TotalTicks / Round);
  }

  //
  // Free allcoated LockValue
  //
  FreePages ((VOID *)LockValue, EFI_SIZE_TO_PAGES (GetSpinLockProperties ()));

  return EFI_SUCCESS;
}
