/** @file

  Copyright (c) 2025, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SmmCpuPerfStandaloneMm.h"

VOID
EFIAPI
MmSemaphoreSyncPerf (
  IN OUT VOID                *Buffer
  )
{
  UINTN                              RoundIndex;
  UINTN                              CpuIndex;
  UINTN                              Round;

  Round = *((UINTN *) Buffer);

  CpuIndex = 0;

  //
  // Get the exising AP CpuIndex
  //
  mCpuService->WhoAmI (mCpuService, &CpuIndex);

  //
  // Notify BSP: AP has ready for test
  //
  ReleaseBsp (mSemaphoreCpu[mBspIndex].Run);

  for (RoundIndex = 0; RoundIndex < Round; RoundIndex ++) {
    //
    // 1. AP to Wait For BSP
    //
    WaitForBsp (mSemaphoreCpu[CpuIndex].Run);

    //
    // 2. AP to Release BSP
    //
    ReleaseBsp (mSemaphoreCpu[mBspIndex].Run);
  }
}

/**
  Semaphore Sync Perf Check:

     Begin Ticks
  1. BSP to Release All APs ----------------------> 1. AP to WaitForBsp

  2. BSP to Wait For AllAPs <---------------------- 2. AP to ReleaseBsp
     End Ticks

  @param[out] SmmCpuSemaphoreSyncData  Return Semaphore Sync Perf Data.
  @param[in]  Round                    Test round.

  @retval EFI_SUCCESS    Retrieved Semaphore Sync Perf Data successfully.

**/
EFI_STATUS
SmmCpuSemaphoreSyncPerf (
  OUT SMM_CPU_SEMAPHORE_SYNC_DATA      *SmmCpuSemaphoreSyncData,
  IN  UINTN                            Round
  )
{
  EFI_STATUS                                   Status;
  UINT64                                       BeginTicks;
  UINT64                                       EndTicks;
  MM_COMPLETION                                Token;
  UINTN                                        RoundIndex;

  ASSERT (SmmCpuSemaphoreSyncData != NULL);
  ZeroMem (SmmCpuSemaphoreSyncData, sizeof (SMM_CPU_SEMAPHORE_SYNC_DATA));

  //
  // Start up all APs for test
  //
  Status = mMpProtocol->BroadcastProcedure (
                          mMpProtocol,
                          (EFI_AP_PROCEDURE2)(UINTN)MmSemaphoreSyncPerf,
                          0,
                          (VOID *) &Round,
                          &Token,
                          NULL
                          );
  if (EFI_ERROR (Status)) {
    return Status;
  }
  DEBUG ((DEBUG_INFO, "[%a] - All APs Started, Wait for all APs ready for test... \n", __FUNCTION__));

  //
  // Wait for all APs ready for test
  //
  WaitForAllAPs (mApCount);
  DEBUG ((DEBUG_INFO, "[%a] - All APs ready for test! \n", __FUNCTION__));

  for (RoundIndex = 0; RoundIndex < Round; RoundIndex ++) {
    //
    // Zero Begin & End for each round
    //
    BeginTicks = 0;
    EndTicks   = 0;

    //
    // BSP: Start CpuSemaphoreSyncPerf test !!!
    //
    BeginTicks = GetPerformanceCounter ();
    //
    // 1. BSP to Release All APs
    //
    ReleaseAllAPs ();

    //
    // 2. BSP to Wait For All APs (mApCount)
    //
    WaitForAllAPs (mApCount);
    EndTicks = GetPerformanceCounter ();

    //
    // Temp record all rounds of AvgTicks
    //
    SmmCpuSemaphoreSyncData->AvgTicks += (EndTicks - BeginTicks);
  }

  //
  // Update returned AvgTicks
  //
  SmmCpuSemaphoreSyncData->AvgTicks = SmmCpuSemaphoreSyncData->AvgTicks / Round;

  //
  // Wait AP finish the Procedure
  //
  Status = mMpProtocol->WaitForProcedure (mMpProtocol, Token);

  return Status;
}
