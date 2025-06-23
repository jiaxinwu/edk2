/** @file
  Implementation of SMM CPU Performance Application.

  Copyright (c) 2025, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <Pi/PiMultiPhase.h>
#include <Library/BaseLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/IoLib.h>
#include <Library/PciLib.h>
#include <Library/ShellLib.h>
#include <Library/LocalApicLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/TimerLib.h>
#include <Protocol/MpService.h>
#include <Protocol/MmCommunication.h>
#include <Guid/PiSmmCommunicationRegionTable.h>
#include <Guid/SmmCpuPerfHob.h>
#include <Register/Intel/Cpuid.h>

//
// String token ID of help message text.
// Shell supports to find help message in the resource section of an application image if
// .MAN file is not found. This global variable is added to make build tool recognizes
// that the help string is consumed by user and then build tool will add the string into
// the resource section. Thus the application can use '-?' option to show help message in
// Shell.
//
GLOBAL_REMOVE_IF_UNREFERENCED EFI_STRING_ID mStringHelpTokenId = STRING_TOKEN (STR_GET_HELP_SMIPERF);

/**
  An array of acpiview command line parameters.
**/
STATIC CONST SHELL_PARAM_ITEM ParamList[] = {
  {L"-round",          TypeValue}, //  Specify the round of each test. 1000 by default.

  {L"-swsmi",          TypeFlag},  //  Perform SW SMI test and parse the output data.
  {L"-b2",             TypeValue}, //  Specify what byte value written to port B2. 0x0 by default. Only valid with -swsmi.

  {L"-bsplock",        TypeFlag},  //  Perform SmmCpuPerfBspLock test and parse the output data.

  {L"-contendedlock",  TypeFlag},  //  Perform SmmCpuPerfContendedLock test and parse the output data.

  {L"-counter",        TypeFlag},  //  Perform SmmCpuPerfCounter test and parse the output data.

  {L"-semsync",        TypeFlag},  //  Perform SmmCpuPerfSemaphoreSync test and parse the output data.

  {NULL,               TypeMax}
};

#define MSR_SMI_COUNT 0x00000034

UINT64
SmmCpuPerfCalculateTscFrequency (
  VOID
  )
{
  UINT64                        CpuIdTscFrequency;
  UINT32                        RegEax;
  UINT32                        RegEbx;
  UINT32                        RegEcx;

  AsmCpuid (CPUID_TIME_STAMP_COUNTER, &RegEax, &RegEbx, &RegEcx, NULL);
  CpuIdTscFrequency = DivU64x32 (MultU64x32 (RegEcx, RegEbx) + (UINT64)(RegEax >> 1), RegEax);

  return CpuIdTscFrequency;
}

EFI_STATUS
PerfSmmCpuSwSmiTest (
  UINT8         B2Value,
  UINTN         Round
  )
{
  UINTN         Index;
  UINT64        Start;
  UINT64        End;

  EFI_TPL       OldTpl;

  UINT64        SmiCountStart;
  UINT64        SmiCountEnd;

  OldTpl = gBS->RaiseTPL (TPL_HIGH_LEVEL);

  SmiCountStart = AsmReadMsr64 (MSR_SMI_COUNT);

  Start = GetPerformanceCounter ();
  for (Index = 0; Index < Round; Index++) {
    //
    // write B2Value to B2 to trigger SW SMI for performance check
    //
    IoWrite8 (0xB2, B2Value);
  }
  End = GetPerformanceCounter ();

  SmiCountEnd = AsmReadMsr64 (MSR_SMI_COUNT);

  gBS->RestoreTPL (OldTpl);

  ASSERT ((SmiCountEnd - SmiCountStart) == Round);

  Print (L"\nSmmCpuPerf: IoWrite 0x%02x to 0xB2, Round: %d\n", B2Value, Round);
  Print (L"\t SMIs happened %d times, Average 1 SMI cost: %llu ns.\n", (SmiCountEnd - SmiCountStart), GetTimeInNanoSecond (End - Start) / (SmiCountEnd - SmiCountStart));

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
PerfSmmCpuFunctionTest (
  IN UINT64                Function,
  IN UINT64                Round
  )
{
  EFI_STATUS                                Status;
  EFI_MM_COMMUNICATION_PROTOCOL             *MmCommunication;
  EDKII_PI_SMM_COMMUNICATION_REGION_TABLE   *PiSmmCommunicationRegionTable;
  EFI_MEMORY_DESCRIPTOR                     *MmCommMemRegion;
  EFI_MM_COMMUNICATE_HEADER                 *CommHeader;
  SMM_CPU_PERF_COMM_BUFFER                  *CommBuffer;
  UINTN                                     CommBufferSize;
  UINTN                                     Index;
  UINTN                                     LockFuncIndex;

  //
  // Step 1: Grab the common buffer header.
  //
  Status = EfiGetSystemConfigurationTable (&gEdkiiPiSmmCommunicationRegionTableGuid, (VOID**)&PiSmmCommunicationRegionTable);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to locate SMM communciation common buffer - %r!\n", __FUNCTION__, Status));
    return Status;
  }

  //
  // Step 2: Grab one that is large enough to hold SMM_CPU_PERF_COMM_BUFFER.
  //
  CommBufferSize = 0;
  MmCommMemRegion = (EFI_MEMORY_DESCRIPTOR*)(PiSmmCommunicationRegionTable + 1);
  for (Index = 0; Index < PiSmmCommunicationRegionTable->NumberOfEntries; Index++) {
    if (MmCommMemRegion->Type == EfiConventionalMemory) {
      CommBufferSize = EFI_PAGES_TO_SIZE ((UINTN)MmCommMemRegion->NumberOfPages);
      if (CommBufferSize >= (sizeof (SMM_CPU_PERF_COMM_BUFFER) + OFFSET_OF (EFI_MM_COMMUNICATE_HEADER, Data))) {
        break;
      }
    }
    MmCommMemRegion = (EFI_MEMORY_DESCRIPTOR*)((UINT8*)MmCommMemRegion + PiSmmCommunicationRegionTable->DescriptorSize);
  }

  if (Index >= PiSmmCommunicationRegionTable->NumberOfEntries) {
    DEBUG ((DEBUG_ERROR, "%a - Could not find a common buffer that is big enough for data!\n", __FUNCTION__));
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Step3: Start to populate contents.
  //
  CommHeader = (EFI_MM_COMMUNICATE_HEADER *) (UINTN) MmCommMemRegion->PhysicalStart;
  CommBufferSize = sizeof (SMM_CPU_PERF_COMM_BUFFER) + OFFSET_OF (EFI_MM_COMMUNICATE_HEADER, Data);
  ZeroMem (CommHeader, CommBufferSize);
  CopyGuid (&CommHeader->HeaderGuid, &gSmmCpuPerfHobGuid);
  CommHeader->MessageLength = sizeof (SMM_CPU_PERF_COMM_BUFFER);
  CommBuffer = (SMM_CPU_PERF_COMM_BUFFER*)(CommHeader->Data);
  CommBuffer->Function = Function;
  CommBuffer->Round    = Round;

  //
  // Step 4: Locate the protocol and signal SMI.
  //
  Status = gBS->LocateProtocol (&gEfiMmCommunicationProtocolGuid, NULL, (VOID**)&MmCommunication);
  if (!EFI_ERROR (Status)) {
    Status = MmCommunication->Communicate (MmCommunication, CommHeader, &CommBufferSize);
    DEBUG ((DEBUG_INFO, "%a - Communicate() = %r\n", __FUNCTION__, Status));
  } else {
    DEBUG ((DEBUG_ERROR, "%a - Failed to locate MmCommunication protocol - %r\n", __FUNCTION__, Status));
    return Status;
  }

  //
  // Step 5: check If everything goes well.
  //
  if (EFI_ERROR (CommBuffer->ReturnStatus)) {
    return (EFI_STATUS)CommBuffer->ReturnStatus;
  }

  //
  // Step 6: print test result.
  //
  switch (Function) {
  case SmmCpuPerfBspLock:
    Print (L"\nSmmCpuPerf: SmmCpuPerfBspLock Test %d Round: \n", Round);
    for (LockFuncIndex = 0; LockFuncIndex < LockFuncMax; LockFuncIndex ++) {
      Print (L"\t SmmCpuBspLockData.AvgTicks[%d] %llu ns.\n", LockFuncIndex, GetTimeInNanoSecond (CommBuffer->SmmCpuPerfData.SmmCpuBspLockData.AvgTicks[LockFuncIndex]));
    }
    break;

  case SmmCpuPerfContendedLock:
    Print (L"\nSmmCpuPerf: SmmCpuPerfContendedLock Test %d Round: \n", Round);
    for (LockFuncIndex = 0; LockFuncIndex < LockFuncMax; LockFuncIndex ++) {
      Print (L"\t SmmCpuContendedLockData.MaxTicks[%d] %llu ns.\n", LockFuncIndex, GetTimeInNanoSecond (CommBuffer->SmmCpuPerfData.SmmCpuContendedLockData.MaxTicks[LockFuncIndex]));
      Print (L"\t SmmCpuContendedLockData.MinTicks[%d] %llu ns.\n", LockFuncIndex, GetTimeInNanoSecond (CommBuffer->SmmCpuPerfData.SmmCpuContendedLockData.MinTicks[LockFuncIndex]));
      Print (L"\t SmmCpuContendedLockData.AvgTicks[%d] %llu ns.\n", LockFuncIndex, GetTimeInNanoSecond (CommBuffer->SmmCpuPerfData.SmmCpuContendedLockData.AvgTicks[LockFuncIndex]));
      Print (L"\t SmmCpuContendedLockData.ApBeginExtremeDiff[%d] %ld.\n", LockFuncIndex, CommBuffer->SmmCpuPerfData.SmmCpuContendedLockData.ApBeginExtremeDiff[LockFuncIndex]);
      Print (L"\t SmmCpuContendedLockData.ApBeginVariance[%d] %ld.\n\n", LockFuncIndex, CommBuffer->SmmCpuPerfData.SmmCpuContendedLockData.ApBeginVariance[LockFuncIndex]);
    }
    break;

  case SmmCpuPerfCounter:
    Print (L"\nSmmCpuPerf: SmmCpuPerfCounter Test %d Round: \n", Round);
    Print (L"\t SmmCpuCounterData.MaxTicks %llu ns.\n", GetTimeInNanoSecond (CommBuffer->SmmCpuPerfData.SmmCpuCounterData.MaxTicks));
    Print (L"\t SmmCpuCounterData.MinTicks %llu ns.\n", GetTimeInNanoSecond (CommBuffer->SmmCpuPerfData.SmmCpuCounterData.MinTicks));
    Print (L"\t SmmCpuCounterData.AvgTicks %llu ns.\n", GetTimeInNanoSecond (CommBuffer->SmmCpuPerfData.SmmCpuCounterData.AvgTicks));
    Print (L"\t SmmCpuCounterData.BspWaitTicks %llu ns.\n", GetTimeInNanoSecond (CommBuffer->SmmCpuPerfData.SmmCpuCounterData.BspWaitTicks));
    break;

  case SmmCpuPerfSemaphoreSync:
    Print (L"\nSmmCpuPerf: SmmCpuPerfSemaphoreSync Test %d Round: \n", Round);
    Print (L"\t SmmCpuSemaphoreSyncData.AvgTicks %llu ns.\n", GetTimeInNanoSecond (CommBuffer->SmmCpuPerfData.SmmCpuSemaphoreSyncData.AvgTicks));
    break;

  default:
    Status = EFI_UNSUPPORTED;
    break;
  }

  return Status;
}

EFI_STATUS
EFIAPI
SmmCpuPerfInit (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_SYSTEM_TABLE     *SystemTable
  )
{
  EFI_STATUS                Status;
  LIST_ENTRY                *ParamPackage;
  CONST CHAR16              *ParamValue;
  UINT8                     B2Value;
  UINTN                     Round;
  EFI_MP_SERVICES_PROTOCOL  *MpServices = NULL;
  UINTN                     NumberOfProcessors = 0;
  UINTN                     NumberOfEnabledProcessors = 0;

  //
  // Initialize the shell lib
  //
  Status = ShellInitialize();
  ASSERT_EFI_ERROR(Status);

  B2Value = 0;
  Round   = 1000;

  Print (L"SmmCpuPerf: Start...\n");

  //
  // Process Command Line arguments
  //
  Status = ShellCommandLineParse (ParamList, &ParamPackage, NULL, TRUE);
  if (EFI_ERROR (Status)) {
    Print (L"SmmCpuPerf: Invalid parameters!\n");
    return SHELL_INVALID_PARAMETER;
  }

  gBS->LocateProtocol (
         &gEfiMpServiceProtocolGuid,
         NULL,
         (VOID**)&MpServices
         );
  ASSERT (MpServices != NULL);

  MpServices->GetNumberOfProcessors (
                MpServices,
                &NumberOfProcessors,
                &NumberOfEnabledProcessors
                );

  Print (L"SmmCpuPerf: Total num of Processors - %d. Enabled Processors - %d. TscFreq - %ld\n", NumberOfProcessors, NumberOfEnabledProcessors, SmmCpuPerfCalculateTscFrequency ());

  ParamValue = ShellCommandLineGetValue (ParamPackage, L"-round");
  if (ParamValue != NULL) {
    Round = ShellStrToUintn (ParamValue);
  }

  if (ShellCommandLineGetFlag (ParamPackage, L"-swsmi")) {
    ParamValue = ShellCommandLineGetValue (ParamPackage, L"-b2");
    if (ParamValue != NULL) {
      B2Value = (UINT8)ShellStrToUintn (ParamValue);
    }
    Status = PerfSmmCpuSwSmiTest (B2Value, Round);
  } else if (ShellCommandLineGetFlag (ParamPackage, L"-bsplock")) {
    Status = PerfSmmCpuFunctionTest (SmmCpuPerfBspLock, Round);
  } else if (ShellCommandLineGetFlag (ParamPackage, L"-contendedlock")) {
    Status = PerfSmmCpuFunctionTest (SmmCpuPerfContendedLock, Round);
  } else if (ShellCommandLineGetFlag (ParamPackage, L"-counter")) {
    Status = PerfSmmCpuFunctionTest (SmmCpuPerfCounter, Round);
  } else if (ShellCommandLineGetFlag (ParamPackage, L"-semsync")) {
    Status = PerfSmmCpuFunctionTest (SmmCpuPerfSemaphoreSync, Round);
  }

  ShellCommandLineFreeVarList (ParamPackage);

  Print (L"SmmCpuPerf: End.\n");

  return EFI_SUCCESS;
}
