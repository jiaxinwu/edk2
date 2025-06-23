/** @file

  Copyright (c) 2025, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _SMM_CPU_PERF_STANDALONEMM_H_
#define _SMM_CPU_PERF_STANDALONEMM_H_

#include <PiMm.h>

#include <Protocol/MpService.h>
#include <Protocol/MmMp.h>
#include <Protocol/SmmCpuService.h>
#include <Guid/MemoryAttributesTable.h>
#include <Guid/SmramMemoryReserve.h>
#include <Guid/MpInformation.h>
#include <Guid/SmmCpuPerfHob.h>

#include <Library/PrintLib.h>
#include <Library/BaseLib.h>
#include <Library/TimerLib.h>
#include <Library/SynchronizationLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PcdLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugAgentLib.h>
#include <Library/UefiLib.h>
#include <Library/HobLib.h>
#include <Library/CpuLib.h>
#include <Library/StandaloneMmMemLib.h>
#include <Library/SmmCpuRendezvousLib.h>

///
/// Semaphore CPU information
///
typedef struct {
  volatile UINT32     *Run;
} SMM_CPU_PERF_SEMAPHORE_CPU;

typedef struct {
  UINT64     Begin;
  UINT64     End;
} BEGIN_END_RECORD;

extern EFI_MM_MP_PROTOCOL                     *mMpProtocol;
extern EFI_SMM_CPU_SERVICE_PROTOCOL           *mCpuService;
extern UINTN                                  mBspIndex;
extern UINTN                                  mApCount;

extern volatile BOOLEAN                       *mPerfRunning;

extern SMM_CPU_PERF_SEMAPHORE_CPU             *mSemaphoreCpu;

#define SMM_CPU_PERF_RUNNING_DELAY            100    /// 100us

/*
  Call this function will cover below Instrs:

    lea         rcx,[Value]
    call        LockInc
  LockInc:
    lock inc    dword ptr [rcx]
    ret
*/
VOID
EFIAPI
LockInc (
  IN      volatile UINT32           *Value
  );

/*
  Call this function will cover below Instrs:

    lea         rcx,[Value]
    call        LockXadd
  LockXadd:
    mov         eax,1
    lock xadd   dword ptr [rcx],eax
    ret
*/
VOID
EFIAPI
LockXadd (
  IN      volatile UINT32           *Value
  );

/*
  Call this function will cover below Instrs:

    lea         rcx,[Value]
    call        LockCmpxchg
  LockCmpxchg:
    mov          edx, LOCK_EXCHANGE_VALUE
    mov          eax, LOCK_COMPARE_VALUE
    lock cmpxchg dword ptr [rcx],edx
    ret
*/
VOID
EFIAPI
LockCmpxchg (
  IN      volatile UINT32           *Value
  );

typedef
VOID
(EFIAPI  *LOCK_FUNCTION)(
  IN      volatile UINT32           *Value
  );

extern LOCK_FUNCTION  mLockFunction[LockFuncMax];


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
  );

/**
  Used for BSP to wait all APs.

  @param   NumberOfAPs      AP number

**/
VOID
WaitForAllAPs (
  IN      UINTN  NumberOfAPs
  );

/**
  Used for BSP to release all APs.

**/
VOID
ReleaseAllAPs (
  VOID
  );

/**
  Used for AP to wait BSP.

  @param      ApSem      IN:  32-bit unsigned integer
                         OUT: original integer 0
**/
VOID
WaitForBsp  (
  IN OUT  volatile UINT32 *ApSem
  );

/**
  Used for AP to release BSP.

  @param      BspSem     IN:  32-bit unsigned integer
                         OUT: original integer + 1
**/
VOID
ReleaseBsp   (
  IN OUT  volatile UINT32  *BspSem
  );


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
  );

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
  );

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
  );

/**
  Semaphore Sync Perf Check:

     Begin Ticks
  1. BSP to Release All APs ----------------------> 1. AP to WaitForBsp

  2. BSP to Wait For All APs <---------------------- 2. AP to ReleaseBsp
     End Ticks

  @param[out] SmmCpuSemaphoreSyncData  Return Semaphore Sync Perf Data.
  @param[in]  Round                    Test round.

  @retval EFI_SUCCESS    Retrieved Semaphore Sync Perf Data successfully.

**/
EFI_STATUS
SmmCpuSemaphoreSyncPerf (
  OUT SMM_CPU_SEMAPHORE_SYNC_DATA      *SmmCpuSemaphoreSyncData,
  IN  UINTN                            Round
  );

#endif
