/** @file

  Copyright (c) 2025, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SmmCpuPerfStandaloneMm.h"

typedef struct {
  volatile UINT32                    *LockValue;
  UINTN                              Round;
  BEGIN_END_RECORD                   *ContendedLockRecord;
} CONTENDED_LOCK_CONTEXT;

VOID
EFIAPI
MmContendedLockPerf (
  IN OUT VOID                *Buffer
  )
{
  CONTENDED_LOCK_CONTEXT             *ContendedLockContext;
  UINTN                              LockFuncIndex;
  UINTN                              RoundIndex;
  UINTN                              CpuIndex;

  ContendedLockContext = (CONTENDED_LOCK_CONTEXT *) Buffer;

  CpuIndex = 0;

  //
  // Get the exising AP CpuIndex
  //
  mCpuService->WhoAmI (mCpuService, &CpuIndex);

  //
  // Notify BSP: AP has ready for test
  //
  ReleaseBsp (mSemaphoreCpu[mBspIndex].Run);

  //
  // Sub function test
  //
  for (LockFuncIndex = 0; LockFuncIndex < LockFuncMax; LockFuncIndex ++) {
    //
    // Round test
    //
    for (RoundIndex = 0; RoundIndex < ContendedLockContext->Round; RoundIndex ++) {
      //
      // Wait for the signal from BSP to begin the perf test:
      // 1. WaitForBsp is to avoid AP get previous round of mPerfRunning flag that before BSP reset mPerfRunning.
      // 2. mPerfRunning flag is to avoid BSP not finsih the "ReleaseAllAPs", this is to make sure all APs can start test near the same time.
      //
      WaitForBsp (mSemaphoreCpu[CpuIndex].Run);

      //
      // Notify BSP: AP has ready to check the mPerfRunning
      //
      ReleaseBsp (mSemaphoreCpu[mBspIndex].Run);
      while (!(*mPerfRunning)) {
        CpuPause ();
      }

      //
      // AP: Start ContendedLockPerf test
      //
      ContendedLockContext->ContendedLockRecord[CpuIndex].Begin = GetPerformanceCounter ();
      mLockFunction[LockFuncIndex] (ContendedLockContext->LockValue);
      ContendedLockContext->ContendedLockRecord[CpuIndex].End = GetPerformanceCounter ();

      //
      // Notify BSP: this AP has finished this round test, so BSP can handler & process this AP collected performance data
      //
      ReleaseBsp (mSemaphoreCpu[mBspIndex].Run);
    }
  }
}

/**
  Contended Lock Perf Check:

     Begin Ticks                                      Begin Ticks
  1. AP1 LockFunc ---------> Shared Mem <--------- 1. AP2 LockFunc
     End Ticks                                        End Ticks

  @param[out] SmmCpuContendedLockData  Return Contended Lock Perf Data.
  @param[in]  Round                    Test round.

  @retval EFI_SUCCESS    Retrieved Contended Lock Perf Data successfully.

**/
EFI_STATUS
SmmCpuContendedLockPerf (
  OUT SMM_CPU_CONTENDED_LOCK_DATA      *SmmCpuContendedLockData,
  IN  UINTN                            Round
  )
{
  EFI_STATUS                                   Status;
  MM_COMPLETION                                Token;
  BEGIN_END_RECORD                             *ContendedLockRecord;
  SMM_CPU_CONTENDED_LOCK_DATA                  ContendedLockDataThisRound;
  UINTN                                        LockFuncIndex;
  UINTN                                        RoundIndex;
  UINTN                                        CpuIndex;
  UINT64                                       BspSignalTicks;
  UINT64                                       AllCpuLockFuncTotalTicks;
  UINT64                                       AllApBeginTotalTicks;
  UINT64                                       ApMaxBeginTicks;
  UINT64                                       ApMinBeginTicks;
  volatile UINT32                              *LockValue;

  CONTENDED_LOCK_CONTEXT                       ContendedLockContext;

  //
  // Allocated to make sure the address is aligned within one exclusive cache line.
  //
  LockValue = (UINT32*) AllocatePages (EFI_SIZE_TO_PAGES (GetSpinLockProperties ()));
  DEBUG ((DEBUG_INFO, "[%a] - LockValue Address : 0x%08x\n", __FUNCTION__, (UINTN) LockValue));

  ASSERT (SmmCpuContendedLockData != NULL);
  ZeroMem (SmmCpuContendedLockData, sizeof (SMM_CPU_CONTENDED_LOCK_DATA));

  //
  // Allocate buffer for all CPU record
  //
  ContendedLockRecord = (BEGIN_END_RECORD *)AllocateZeroPool (sizeof (BEGIN_END_RECORD) * (gMmst->NumberOfCpus));
  ASSERT (ContendedLockRecord != NULL);

  //
  // Start up all APs for test
  //
  ContendedLockContext.LockValue           = LockValue;
  ContendedLockContext.Round               = Round;
  ContendedLockContext.ContendedLockRecord = ContendedLockRecord;
  Status = mMpProtocol->BroadcastProcedure (
                          mMpProtocol,
                          (EFI_AP_PROCEDURE2) (UINTN) MmContendedLockPerf,
                          0,
                          (VOID *) &ContendedLockContext,
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

  for (LockFuncIndex = 0; LockFuncIndex < LockFuncMax; LockFuncIndex ++) {
    for (RoundIndex = 0; RoundIndex < Round; RoundIndex ++) {
      //
      // Zero buffer for each CPU record
      //
      ZeroMem (ContendedLockRecord, sizeof (BEGIN_END_RECORD) * (gMmst->NumberOfCpus));

      //
      // Zero buffer for each round data
      //
      ZeroMem (&ContendedLockDataThisRound, sizeof (SMM_CPU_CONTENDED_LOCK_DATA));

      //
      // Reset LockValue to 0 for each round test
      //
      *LockValue = 0;

      //
      // Signal APs to begin this round perf test
      //
      ReleaseAllAPs ();

      //
      // Wait for ALL APs realdy to poll the mPerfRunning
      //
      WaitForAllAPs (mApCount);
      MicroSecondDelay (SMM_CPU_PERF_RUNNING_DELAY); /// This is to make sure all Aps in the while loop before BSP write mPerfRunning flag.

      //
      // After BSP MicroSecond Delay, BSP notify AP start test near the same time
      //
      BspSignalTicks = GetPerformanceCounter ();
      *mPerfRunning  = TRUE;

      //
      // BSP: Start ContendedLockPerf test
      //
      ContendedLockRecord[mBspIndex].Begin = GetPerformanceCounter ();
      mLockFunction[LockFuncIndex] (LockValue);
      ContendedLockRecord[mBspIndex].End = GetPerformanceCounter ();

      //
      // Wait for all APs finish this round test, then can process all collected data
      //
      WaitForAllAPs (mApCount);

      //
      // Sanity check
      //
      if (LockFuncIndex == LockFuncLockInc) {
        ASSERT (*LockValue == gMmst->NumberOfCpus);
      } else if (LockFuncIndex == LockFuncLockXadd) {
        ASSERT (*LockValue == gMmst->NumberOfCpus);
      } else if (LockFuncIndex == LockFuncLockCmpxchg) {
        ASSERT (*LockValue == 0);
      } else {
        ASSERT (FALSE);
      }

      //
      // Reset *mPerfRunning = FALSE for next lock prefix perf test
      //
      *mPerfRunning = FALSE;

      //
      // Process this round Record Data !!!
      //
      AllCpuLockFuncTotalTicks                                   = 0;
      AllApBeginTotalTicks                                       = 0;
      ApMaxBeginTicks                                            = 0;
      ApMinBeginTicks                                            = MAX_UINT64;
      ContendedLockDataThisRound.MinTicks[LockFuncIndex]         = MAX_UINT64;
      for (CpuIndex = 0; CpuIndex < gMmst->NumberOfCpus; CpuIndex ++) {
        ASSERT (ContendedLockRecord[CpuIndex].End > ContendedLockRecord[CpuIndex].Begin);
        if (ContendedLockRecord[CpuIndex].End <= ContendedLockRecord[CpuIndex].Begin) {
          DEBUG ((DEBUG_ERROR, "[%a] - CPU %4d End Tickets (%ld) <= Begin Tickets (%ld) in Round %d for LockFunc %d!\n", __FUNCTION__, CpuIndex, ContendedLockRecord[CpuIndex].End, ContendedLockRecord[CpuIndex].Begin, RoundIndex, LockFuncIndex));
        }

        DEBUG ((DEBUG_INFO, "[%a] - CPU %4d: Begin Tickets in Round %d for LockFunc %d = %ld\n", __FUNCTION__, CpuIndex, RoundIndex, LockFuncIndex, ContendedLockRecord[CpuIndex].Begin));
        DEBUG ((DEBUG_INFO, "[%a] - CPU %4d: End Tickets in Round %d for LockFunc %d   = %ld\n", __FUNCTION__, CpuIndex, RoundIndex, LockFuncIndex, ContendedLockRecord[CpuIndex].End));
        DEBUG ((DEBUG_INFO, "[%a] - CPU %4d: LockFunc Cost Tickets (End - Begin) in Round %d for LockFunc %d   = %ld\n", __FUNCTION__, CpuIndex, RoundIndex, LockFuncIndex, ContendedLockRecord[CpuIndex].End - ContendedLockRecord[CpuIndex].Begin));
        DEBUG ((DEBUG_INFO, "[%a] - CPU %4d: Get mPerfRunning Cost Tickets (AP Begin - BspSignalTicks) in Round %d for LockFunc %d  = %ld\n", __FUNCTION__, CpuIndex, RoundIndex, LockFuncIndex, ContendedLockRecord[CpuIndex].Begin - BspSignalTicks));

        if (ContendedLockDataThisRound.MaxTicks[LockFuncIndex] < ContendedLockRecord[CpuIndex].End - ContendedLockRecord[CpuIndex].Begin) {
          ContendedLockDataThisRound.MaxTicks[LockFuncIndex] = ContendedLockRecord[CpuIndex].End - ContendedLockRecord[CpuIndex].Begin;
        }

        if (ContendedLockDataThisRound.MinTicks[LockFuncIndex] > ContendedLockRecord[CpuIndex].End - ContendedLockRecord[CpuIndex].Begin) {
          ContendedLockDataThisRound.MinTicks[LockFuncIndex] = ContendedLockRecord[CpuIndex].End - ContendedLockRecord[CpuIndex].Begin;
        }

        AllCpuLockFuncTotalTicks += (ContendedLockRecord[CpuIndex].End - ContendedLockRecord[CpuIndex].Begin);

        if (CpuIndex != mBspIndex) {
          if (ApMaxBeginTicks < ContendedLockRecord[CpuIndex].Begin) {
            ApMaxBeginTicks = ContendedLockRecord[CpuIndex].Begin;
          }

          if (ApMinBeginTicks > ContendedLockRecord[CpuIndex].Begin) {
            ApMinBeginTicks = ContendedLockRecord[CpuIndex].Begin;
          }

          AllApBeginTotalTicks += ContendedLockRecord[CpuIndex].Begin;
        }
      }

      ContendedLockDataThisRound.AvgTicks[LockFuncIndex]            = AllCpuLockFuncTotalTicks / gMmst->NumberOfCpus;
      ContendedLockDataThisRound.ApBeginExtremeDiff[LockFuncIndex]  = ApMaxBeginTicks - ApMinBeginTicks;
      for (CpuIndex = 0; CpuIndex < gMmst->NumberOfCpus; CpuIndex++) {
        if (CpuIndex != mBspIndex) {
          ContendedLockDataThisRound.ApBeginVariance[LockFuncIndex] += ((ContendedLockRecord[CpuIndex].Begin - (AllApBeginTotalTicks / mApCount)) * (ContendedLockRecord[CpuIndex].Begin - (AllApBeginTotalTicks / mApCount)) / mApCount);
        }
      }

      DEBUG ((DEBUG_INFO, "[%a] - AP Avg Begin Tickets in Round %d for LockFunc %d = %ld\n", __FUNCTION__, RoundIndex, LockFuncIndex, AllApBeginTotalTicks / mApCount));
      DEBUG ((DEBUG_INFO, "[%a] - AP ApBeginExtremeDiff of Begin (Max Begin Tickets - Min Begin Tickets) in Round %d for LockFunc %d = %ld\n", __FUNCTION__, RoundIndex, LockFuncIndex, ContendedLockDataThisRound.ApBeginExtremeDiff[LockFuncIndex]));
      DEBUG ((DEBUG_INFO, "[%a] - AP ApBeginVariance of Begin in Round %d for LockFunc %d = %ld\n", __FUNCTION__, RoundIndex, LockFuncIndex, ContendedLockDataThisRound.ApBeginVariance[LockFuncIndex]));

      //
      // Temp record all rounds of MaxTicks & MinTicks & AvgTicks & ApBeginExtremeDiff & ApBeginVariance
      //
      SmmCpuContendedLockData->MaxTicks[LockFuncIndex]           += ContendedLockDataThisRound.MaxTicks[LockFuncIndex];
      SmmCpuContendedLockData->MinTicks[LockFuncIndex]           += ContendedLockDataThisRound.MinTicks[LockFuncIndex];
      SmmCpuContendedLockData->AvgTicks[LockFuncIndex]           += ContendedLockDataThisRound.AvgTicks[LockFuncIndex];
      SmmCpuContendedLockData->ApBeginExtremeDiff[LockFuncIndex] += ContendedLockDataThisRound.ApBeginExtremeDiff[LockFuncIndex];
      SmmCpuContendedLockData->ApBeginVariance[LockFuncIndex]    += ContendedLockDataThisRound.ApBeginVariance[LockFuncIndex];
    }

    //
    // Update returned MaxTicks & MinTicks & AvgTicks & ApBeginExtremeDiff & ApBeginVariance
    //
    SmmCpuContendedLockData->MaxTicks[LockFuncIndex]           = SmmCpuContendedLockData->MaxTicks[LockFuncIndex] / Round;
    SmmCpuContendedLockData->MinTicks[LockFuncIndex]           = SmmCpuContendedLockData->MinTicks[LockFuncIndex] / Round;
    SmmCpuContendedLockData->AvgTicks[LockFuncIndex]           = SmmCpuContendedLockData->AvgTicks[LockFuncIndex] / Round;
    SmmCpuContendedLockData->ApBeginExtremeDiff[LockFuncIndex] = SmmCpuContendedLockData->ApBeginExtremeDiff[LockFuncIndex] / Round;
    SmmCpuContendedLockData->ApBeginVariance[LockFuncIndex]    = SmmCpuContendedLockData->ApBeginVariance[LockFuncIndex] / Round;
  }

  //
  // Wait AP finish the Procedure
  //
  Status = mMpProtocol->WaitForProcedure (mMpProtocol, Token);

  //
  // Free buffer for all CPU record
  //
  FreePool (ContendedLockRecord);
  ContendedLockRecord = NULL;

  //
  // Free allcoated LockValue
  //
  FreePages ((VOID *)LockValue, EFI_SIZE_TO_PAGES (GetSpinLockProperties ()));

  return Status;
}
