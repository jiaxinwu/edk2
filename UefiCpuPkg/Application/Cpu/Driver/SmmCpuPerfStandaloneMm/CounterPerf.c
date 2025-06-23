/** @file

  Copyright (c) 2025, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SmmCpuPerfStandaloneMm.h"

typedef struct {
  volatile UINT32                    *ApCounter;
  UINTN                              Round;
  BEGIN_END_RECORD                   *CounterBeginEndRecord;
} COUNTER_PERF_CONTEXT;

VOID
EFIAPI
MmCounterPerf (
  IN OUT VOID                *Buffer
  )
{
  COUNTER_PERF_CONTEXT               *CounterPerfContext;
  UINTN                              RoundIndex;
  UINTN                              CpuIndex;

  CounterPerfContext = (COUNTER_PERF_CONTEXT *) Buffer;

  CpuIndex = 0;

  //
  // Get the exising AP CpuIndex
  //
  mCpuService->WhoAmI (mCpuService, &CpuIndex);

  //
  // Notify BSP: AP has ready for test
  //
  ReleaseBsp (mSemaphoreCpu[mBspIndex].Run);

  for (RoundIndex = 0; RoundIndex < CounterPerfContext->Round; RoundIndex ++) {
    //
    // Wait for the signal from BSP to begin this round perf test:
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
    // AP: Start CounterPerf test
    //
    CounterPerfContext->CounterBeginEndRecord[CpuIndex].Begin = GetPerformanceCounter ();
    CpuCountIncrement (CounterPerfContext->ApCounter);
    CounterPerfContext->CounterBeginEndRecord[CpuIndex].End = GetPerformanceCounter ();

    //
    // Notify BSP: this AP has finished this round test, so BSP can handler & process this AP collected performance data
    //
    ReleaseBsp (mSemaphoreCpu[mBspIndex].Run);
  }
}


/**
  Counter Perf Check:

     Begin Ticks                                                   Begin Ticks
  1. BSP to Wait all APs arrive Counter <---------------------- 1. AP to CpuCountIncrement
     End Ticks                                                     End Ticks

  @param[out] SmmCpuCounterData             Return AP arrive Counter Perf Data inculding
                                            BSP wait time.
  @param[in]  Round                         Test round.

  @retval EFI_SUCCESS    Retrieved Counter Perf Data successfully.

**/
EFI_STATUS
SmmCpuCounterPerf (
  OUT SMM_CPU_COUNTER_DATA                 *SmmCpuCounterData,
  IN  UINTN                                Round
  )
{
  EFI_STATUS                                   Status;
  MM_COMPLETION                                Token;
  BEGIN_END_RECORD                             *CounterBeginEndRecord;
  SMM_CPU_COUNTER_DATA                         SmmCpuCounterDataThisRound;
  UINTN                                        RoundIndex;
  UINTN                                        CpuIndex;
  UINT64                                       BspSignalTicks;
  UINT64                                       AllApTotalTicks;
  volatile UINT32                              *ApCounter;

  COUNTER_PERF_CONTEXT                         CounterPerfContext;

  //
  // Allocated to make sure the address is aligned within one exclusive cache line.
  //
  ApCounter = (UINT32 *)AllocatePages (EFI_SIZE_TO_PAGES (GetSpinLockProperties ()));
  DEBUG ((DEBUG_INFO, "[%a] - ApCounter Address : 0x%08x\n", __FUNCTION__, (UINTN)ApCounter));

  ASSERT (SmmCpuCounterData != NULL);
  ZeroMem (SmmCpuCounterData, sizeof (SMM_CPU_COUNTER_DATA));

  //
  // Allocate buffer for all CPU record
  //
  CounterBeginEndRecord = NULL;
  CounterBeginEndRecord = (BEGIN_END_RECORD *)AllocateZeroPool (sizeof (BEGIN_END_RECORD) * (gMmst->NumberOfCpus));
  ASSERT (CounterBeginEndRecord != NULL);

  //
  // Start up all APs for test
  //
  CounterPerfContext.ApCounter                = ApCounter;
  CounterPerfContext.Round                    = Round;
  CounterPerfContext.CounterBeginEndRecord    = CounterBeginEndRecord;
  Status = mMpProtocol->BroadcastProcedure (
                          mMpProtocol,
                          (EFI_AP_PROCEDURE2) (UINTN) MmCounterPerf,
                          0,
                          (VOID *) &CounterPerfContext,
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
    // Zero buffer for each CPU record
    //
    ZeroMem (CounterBeginEndRecord, sizeof (BEGIN_END_RECORD) * (gMmst->NumberOfCpus));

    //
    // Zero buffer for each round data
    //
    ZeroMem (&SmmCpuCounterDataThisRound, sizeof (SMM_CPU_COUNTER_DATA));

    //
    // Reset ApCounter to 0 for each round test
    //
    *ApCounter = 0;

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
    *mPerfRunning = TRUE;

    //
    // BSP: Start CounterPerf test
    //
    CounterBeginEndRecord[mBspIndex].Begin = GetPerformanceCounter ();
    while (*ApCounter != mApCount) {
      CpuPause ();
    }
    CounterBeginEndRecord[mBspIndex].End = GetPerformanceCounter ();

    //
    // Wait for all APs finish this round test, then can process all collected data
    //
    WaitForAllAPs (mApCount);

    //
    // Reset *mPerfRunning = FALSE for next round perf test
    //
    *mPerfRunning = FALSE;

    //
    // Process this round Record Data
    //
    AllApTotalTicks                                  = 0;
    SmmCpuCounterDataThisRound.MinTicks = MAX_UINT64;
    for (CpuIndex = 0; CpuIndex < gMmst->NumberOfCpus; CpuIndex ++) {
      ASSERT (CounterBeginEndRecord[CpuIndex].End > CounterBeginEndRecord[CpuIndex].Begin);
      if (CounterBeginEndRecord[CpuIndex].End <= CounterBeginEndRecord[CpuIndex].Begin) {
        DEBUG ((DEBUG_ERROR, "[%a] - CPU %4d End Tickets (%ld) <= Begin Tickets (%ld) in Round %d!\n", __FUNCTION__, CpuIndex, CounterBeginEndRecord[CpuIndex].End, CounterBeginEndRecord[CpuIndex].Begin, RoundIndex));
      }

      DEBUG ((DEBUG_INFO, "[%a] - CPU %4d: Begin Tickets in Round %d = %ld\n", __FUNCTION__, CpuIndex, RoundIndex, CounterBeginEndRecord[CpuIndex].Begin));
      DEBUG ((DEBUG_INFO, "[%a] - CPU %4d: End Tickets in Round %d   = %ld\n", __FUNCTION__, CpuIndex, RoundIndex, CounterBeginEndRecord[CpuIndex].End));
      DEBUG ((DEBUG_INFO, "[%a] - CPU %4d: CpuCountIncrement Cost Tickets (End - Begin) in Round %d   = %ld\n", __FUNCTION__, CpuIndex, RoundIndex, CounterBeginEndRecord[CpuIndex].End - CounterBeginEndRecord[CpuIndex].Begin));
      DEBUG ((DEBUG_INFO, "[%a] - CPU %4d: Get mPerfRunning Cost Tickets (AP Begin - BspSignalTicks) in Round %d  = %ld\n", __FUNCTION__, CpuIndex, RoundIndex, CounterBeginEndRecord[CpuIndex].Begin - BspSignalTicks));

      if (CpuIndex == mBspIndex) {
        SmmCpuCounterDataThisRound.BspWaitTicks = CounterBeginEndRecord[CpuIndex].End - CounterBeginEndRecord[CpuIndex].Begin;
      } else {
        if (SmmCpuCounterDataThisRound.MaxTicks < CounterBeginEndRecord[CpuIndex].End - CounterBeginEndRecord[CpuIndex].Begin) {
          SmmCpuCounterDataThisRound.MaxTicks = CounterBeginEndRecord[CpuIndex].End - CounterBeginEndRecord[CpuIndex].Begin;
        }

        if (SmmCpuCounterDataThisRound.MinTicks > CounterBeginEndRecord[CpuIndex].End - CounterBeginEndRecord[CpuIndex].Begin) {
          SmmCpuCounterDataThisRound.MinTicks = CounterBeginEndRecord[CpuIndex].End - CounterBeginEndRecord[CpuIndex].Begin;
        }

        AllApTotalTicks += (CounterBeginEndRecord[CpuIndex].End - CounterBeginEndRecord[CpuIndex].Begin);
      }
    }

    SmmCpuCounterDataThisRound.AvgTicks = (AllApTotalTicks / mApCount);

    //
    // Temp record all rounds of MaxTicks & MinTicks & AvgTicks & BspWaitTicks
    //
    SmmCpuCounterData->MaxTicks        += SmmCpuCounterDataThisRound.MaxTicks;
    SmmCpuCounterData->MinTicks        += SmmCpuCounterDataThisRound.MinTicks;
    SmmCpuCounterData->AvgTicks        += SmmCpuCounterDataThisRound.AvgTicks;
    SmmCpuCounterData->BspWaitTicks    += SmmCpuCounterDataThisRound.BspWaitTicks;
  }

  //
  // Update returned MaxTicks & MinTicks & AvgTicks & BspWaitTicks
  //
  SmmCpuCounterData->MaxTicks        = SmmCpuCounterData->MaxTicks / Round;
  SmmCpuCounterData->MinTicks        = SmmCpuCounterData->MinTicks / Round;
  SmmCpuCounterData->AvgTicks        = SmmCpuCounterData->AvgTicks / Round;
  SmmCpuCounterData->BspWaitTicks    = SmmCpuCounterData->BspWaitTicks / Round;

  //
  // Wait AP finish the Procedure
  //
  Status = mMpProtocol->WaitForProcedure (mMpProtocol, Token);

  //
  // Free buffer for all CPU record
  //
  FreePool (CounterBeginEndRecord);
  CounterBeginEndRecord = NULL;

  //
  // Free allcoated ApCounter
  //
  FreePages ((VOID*) ApCounter, EFI_SIZE_TO_PAGES (GetSpinLockProperties ()));

  return Status;
}
