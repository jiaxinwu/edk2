/** @file

  Copyright (c) 2025, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SmmCpuPerfStandaloneMm.h"

EFI_HANDLE                                   mSmmCpuPerfHandle = NULL;
EFI_MM_MP_PROTOCOL                           *mMpProtocol = NULL;
EFI_SMM_CPU_SERVICE_PROTOCOL                 *mCpuService = NULL;
UINTN                                        mBspIndex;
UINTN                                        mApCount;

//
// Flag to indicate all APs can start perf test
// Make sure it has exclusive cacheline since CPU need maintain its Cache Coherency
//
volatile BOOLEAN                             *mPerfRunning;

//
// Semaphore for each Cpu sync  to run
//
SMM_CPU_PERF_SEMAPHORE_CPU                   *mSemaphoreCpu       = NULL;

//
// Only Used for Semaphore Memory Free
//
UINTN                                        *mSemaphoreBlock     = NULL;
UINTN                                        mSemaphoreBlockPages = 0;

VOID
InitializeSmmCpuPerfSemaphore (
  VOID
  )
{
  UINTN  ProcessorCount;
  UINTN  OneSemaphoreSize;
  UINTN  TotalSemaphoreSize;
  UINTN  SemaphoreAddr;
  UINTN  CpuIndex;

  ProcessorCount = gMmst->NumberOfCpus;

  //
  // Allocate for mSemaphoreCpu
  //
  mSemaphoreCpu = (SMM_CPU_PERF_SEMAPHORE_CPU *) AllocatePages (EFI_SIZE_TO_PAGES (sizeof (SMM_CPU_PERF_SEMAPHORE_CPU) * ProcessorCount));
  ASSERT (mSemaphoreCpu != NULL);

  //
  // Allocate for Semaphore in the mSemaphoreCpu
  //
  OneSemaphoreSize      = GetSpinLockProperties ();
  TotalSemaphoreSize    = (sizeof (SMM_CPU_PERF_SEMAPHORE_CPU) / sizeof (VOID*)) * OneSemaphoreSize * ProcessorCount;
  DEBUG ((DEBUG_INFO, "One SMM CPU Perf Semaphore Size    = 0x%x\n", OneSemaphoreSize));
  DEBUG ((DEBUG_INFO, "Total SMM CPU Perf Semaphores Size = 0x%x\n", TotalSemaphoreSize));

  mSemaphoreBlockPages = EFI_SIZE_TO_PAGES (TotalSemaphoreSize);
  mSemaphoreBlock      = AllocatePages (mSemaphoreBlockPages);
  ASSERT (mSemaphoreBlock != NULL);
  ZeroMem (mSemaphoreBlock, TotalSemaphoreSize);

  SemaphoreAddr = (UINTN) mSemaphoreBlock;

  for (CpuIndex = 0; CpuIndex < ProcessorCount; CpuIndex++) {
    mSemaphoreCpu[CpuIndex].Run = (UINT32 *)(SemaphoreAddr + (TotalSemaphoreSize / ProcessorCount) * CpuIndex);
    DEBUG ((DEBUG_INFO, "[%a] - mSemaphoreCpu[%d].Run Address: 0x%08x\n", __FUNCTION__, CpuIndex, (UINTN) mSemaphoreCpu[CpuIndex].Run));

    *(mSemaphoreCpu[CpuIndex].Run) = 0;
  }
}

EFI_STATUS
EFIAPI
SmmCpuPerfCommunciate (
  IN     EFI_HANDLE                   DispatchHandle,
  IN     CONST VOID                   *RegisterContext,
  IN OUT VOID                         *CommBuffer,
  IN OUT UINTN                        *CommBufferSize
  )
{
  EFI_STATUS                            Status;
  SMM_CPU_PERF_COMM_BUFFER              *CommParams;

  Status = EFI_SUCCESS;

  DEBUG ((DEBUG_INFO, "%a()\n", __FUNCTION__));

  //
  // If input is invalid, stop processing this SMI
  //
  if (CommBuffer == NULL || CommBufferSize == NULL) {
    return EFI_SUCCESS;
  }

  if (*CommBufferSize != sizeof (SMM_CPU_PERF_COMM_BUFFER)) {
    DEBUG ((DEBUG_ERROR, "[%a] MM Communication buffer size is invalid for this handler!\n", __FUNCTION__));
    return EFI_ACCESS_DENIED;
  }

  //
  // Bring all Aps in SMM to simplify the test
  //
  Status = SmmWaitForAllProcessor (TRUE);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Initialize mBspIndex & mApCount
  // Note: Assume no cpu hot-plug support & no smm blocked & disabled
  //       support since "mApCount = gMmst->NumberOfCpus - 1".
  //
  mCpuService->WhoAmI (mCpuService, &mBspIndex);
  mApCount = gMmst->NumberOfCpus - 1;
  DEBUG ((DEBUG_INFO, "[%a] - Bsp Index is [%d]\n", __FUNCTION__, mBspIndex));

  //
  // Initialize mPerfRunning
  // Allocated to make sure the address is aligned within one exclusive cache line.
  //
  mPerfRunning = (BOOLEAN *)AllocatePages (EFI_SIZE_TO_PAGES (GetSpinLockProperties ()));
  DEBUG ((DEBUG_INFO, "[%a] - mPerfRunning Address : 0x%08x\n", __FUNCTION__, (UINTN)mPerfRunning));

  *mPerfRunning = FALSE;

  //
  // Initialize CPU Semaphore
  //
  InitializeSmmCpuPerfSemaphore ();

  //
  // Farm out the job to individual functions based on what was requested.
  //
  CommParams = (SMM_CPU_PERF_COMM_BUFFER *)CommBuffer;
  switch (CommParams->Function) {
  case SmmCpuPerfBspLock:
    DEBUG ((DEBUG_INFO, "[%a] - Function requested: SmmCpuPerfBspLock\n", __FUNCTION__));
    Status = SmmCpuBspLockPerf (&CommParams->SmmCpuPerfData.SmmCpuBspLockData, CommParams->Round);
    break;

  case SmmCpuPerfContendedLock:
    DEBUG ((DEBUG_INFO, "[%a] - Function requested: SmmCpuPerfContendedLock\n", __FUNCTION__));
    Status = SmmCpuContendedLockPerf (&CommParams->SmmCpuPerfData.SmmCpuContendedLockData, CommParams->Round);
    break;

  case SmmCpuPerfCounter:
    DEBUG ((DEBUG_INFO, "[%a] - Function requested: SmmCpuCounterPerf\n", __FUNCTION__));
    Status = SmmCpuCounterPerf (&CommParams->SmmCpuPerfData.SmmCpuCounterData, CommParams->Round);
    break;

  case SmmCpuPerfSemaphoreSync:
    DEBUG ((DEBUG_INFO, "[%a] - Function requested: SmmCpuPerfSemaphoreSync\n", __FUNCTION__));
    Status = SmmCpuSemaphoreSyncPerf (&CommParams->SmmCpuPerfData.SmmCpuSemaphoreSyncData, CommParams->Round);
    break;

  default:
    DEBUG ((DEBUG_INFO, "[%a] - Unknown function %d!\n", __FUNCTION__, CommParams->Function));
    Status = EFI_UNSUPPORTED;
    break;
  }

  //
  // Free SmmCpuPerf Semaphore buffer
  //
  FreePages (mSemaphoreBlock, mSemaphoreBlockPages);
  FreePages (mSemaphoreCpu, EFI_SIZE_TO_PAGES (sizeof (SMM_CPU_PERF_SEMAPHORE_CPU) * gMmst->NumberOfCpus));

  //
  // Free allcoated mPerfRunning
  //
  FreePages ((VOID*) mPerfRunning, EFI_SIZE_TO_PAGES (GetSpinLockProperties ()));

  CommParams->ReturnStatus = (UINT64) Status;

  return EFI_SUCCESS;
}

/**
  The module Entry Point of driver.

  @param  ImageHandle    The firmware allocated handle for the EFI image.
  @param  SystemTable    A pointer to the MM System Table.

  @retval EFI_SUCCESS    The entry point is executed successfully.
  @retval Other          Some error occurs when executing this entry point.

**/
EFI_STATUS
EFIAPI
SmmCpuPerfStandaloneMmEntry (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_MM_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                Status;

  //
  // Locate SMM CpuService protocol
  //
  Status = gMmst->MmLocateProtocol (&gEfiSmmCpuServiceProtocolGuid, NULL, (VOID**)&mCpuService);
  ASSERT_EFI_ERROR (Status);

  //
  // locate SMM MP protocol
  //
  Status = gMmst->MmLocateProtocol (&gEfiMmMpProtocolGuid, NULL, (VOID**)&mMpProtocol);
  ASSERT_EFI_ERROR (Status);

  //
  // Register a handler to communicate the SmmCpuPerf data between MM and Non-MM
  //
  Status = gMmst->MmiHandlerRegister (SmmCpuPerfCommunciate, &gSmmCpuPerfHobGuid, &mSmmCpuPerfHandle);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[%a] Failed to register handler for SmmCpuPerf data- %r!\n", __FUNCTION__, Status));
  }

  DEBUG ((DEBUG_INFO, "SmmCpuPerfStandaloneMmEntry, Status: %r\n", Status));

  return EFI_SUCCESS;
}

/**
  Unloads an image.

  @param[in] ImageHandle        Handle that identifies the image to be unloaded.

  @retval EFI_SUCCESS           The image has been unloaded.
  @retval EFI_INVALID_PARAMETER ImageHandle is not a valid image handle.

**/
EFI_STATUS
EFIAPI
SmmCpuPerfStandaloneMmUnload (
  IN EFI_HANDLE  ImageHandle
  )
{
  EFI_STATUS  Status;

  Status = EFI_SUCCESS;

  if (mSmmCpuPerfHandle != NULL) {
    Status = gMmst->MmiHandlerUnRegister (mSmmCpuPerfHandle);
  }

  DEBUG ((DEBUG_INFO, "PiCpuStandaloneMmUnload, Status: %r\n", Status));
  return Status;
}
