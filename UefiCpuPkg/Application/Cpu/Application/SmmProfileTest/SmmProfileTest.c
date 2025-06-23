/** @file

  Copyright (c) 2025, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SmmProfileTest.h"

//
// String token ID of help message text.
// Shell supports to find help message in the resource section of an application image if
// .MAN file is not found. This global variable is added to make build tool recognizes
// that the help string is consumed by user and then build tool will add the string into
// the resource section. Thus the application can use '-?' option to show help message in
// Shell.
//
GLOBAL_REMOVE_IF_UNREFERENCED EFI_STRING_ID  mStringHelpTokenId = STRING_TOKEN (STR_GET_HELP_SMMPROFILETEST);

EFI_HII_HANDLE  mSmmProfileTestHiiHandle = NULL;

/**
  An array of acpiview command line parameters.
**/
STATIC CONST SHELL_PARAM_ITEM  ParamList[] = {
  { L"-dump",         TypeFlag  },   //  Perform SMM Profile data dump.
  { L"-clr",          TypeFlag  },   //  Clear the existing SMM Profile count.
  { L"-mmreschob",    TypeFlag  },   //  Get the MM resource hob info.
  { L"-test",         TypeFlag  },   //  Perform address range from StartAddress to StopAddress.
  { L"-StartAddress", TypeValue },   //  Require access start address (0-4K address range is not allowed due to NULL point detect feature).
  { L"-StopAddress",  TypeValue },   //  Optional access stop address (default will be set to the StartAddress).
  { L"-IntervalSize", TypeValue },   //  Optional range interval size (min 2MB).
  { NULL,             TypeMax   }
};

//
// Use for saving SMM Profile data information
//
EFI_GUID            mSmmProfileGuid = SMM_PROFILE_GUID;
SMM_PROFILE_HEADER  *mSmmProfileBase;

//
// Use for saving SMM driver image information
//
IMAGE_STRUCT  mImageStruct[MAX_NUM_OF_IMAGE_STRUCT];
UINTN         mImageStructCountMax;

//
// Use for saving SMM memory reseource hob information
//
EFI_HOB_RESOURCE_DESCRIPTOR  mRescHob[MAX_NUM_OF_RESCHOB_STRUCT];
UINTN                        mRescHobCount;

//
// Use for mapping memory address type to short name
//
EFI_MEMORY_DESCRIPTOR  *mMemoryMap = NULL;
UINTN                  mMemoryMapSize;
UINTN                  mDescriptorSize;

CHAR16  mUnknownStr[11];
CHAR16  *mMemoryTypeShortName[] = {
  L"Reserved",
  L"LoaderCode",
  L"LoaderData",
  L"BS_Code",
  L"BS_Data",
  L"RT_Code",
  L"RT_Data",
  L"Available",
  L"Unusable",
  L"ACPI_Recl",
  L"ACPI_NVS",
  L"MMIO",
  L"MMIO_Port",
  L"PalCode",
  L"Persistent",
};

/**
  Retrieve HII package list from ImageHandle and publish to HII database.

  @param ImageHandle            The image handle of the process.

  @return HII handle.
**/
EFI_HII_HANDLE
InitializeHiiPackage (
  EFI_HANDLE  ImageHandle
  )
{
  EFI_STATUS                   Status;
  EFI_HII_PACKAGE_LIST_HEADER  *PackageList;
  EFI_HII_HANDLE               HiiHandle;

  //
  // Retrieve HII package list from ImageHandle
  //
  Status = gBS->OpenProtocol (
                  ImageHandle,
                  &gEfiHiiPackageListProtocolGuid,
                  (VOID **)&PackageList,
                  ImageHandle,
                  NULL,
                  EFI_OPEN_PROTOCOL_GET_PROTOCOL
                  );
  ASSERT_EFI_ERROR (Status);
  if (EFI_ERROR (Status)) {
    return NULL;
  }

  //
  // Publish HII package list to HII Database.
  //
  Status = gHiiDatabase->NewPackageList (
                           gHiiDatabase,
                           PackageList,
                           NULL,
                           &HiiHandle
                           );
  ASSERT_EFI_ERROR (Status);
  if (EFI_ERROR (Status)) {
    return NULL;
  }

  return HiiHandle;
}

/**
  Find the driver image based on address.

  @param[in] Address         The address to match the driver image
**/
CHAR8 *
AddressToImageName (
  IN UINTN  Address
  )
{
  UINTN  Index;

  for (Index = 0; Index < mImageStructCountMax; Index++) {
    if ((Address >= mImageStruct[Index].ImageBase) &&
        (Address < mImageStruct[Index].ImageBase + mImageStruct[Index].ImageSize))
    {
      return mImageStruct[Index].PdbString;
    }
  }

  return "???";   // UNKNOWN_NAME
}

/**
  Convert EFI memory type to short name mMemoryTypeShortName.

  @param[in] Type         The EFI memory type
**/
CHAR16 *
ShortNameOfMemoryType (
  IN UINT32  Type
  )
{
  if (Type < sizeof (mMemoryTypeShortName) / sizeof (mMemoryTypeShortName[0])) {
    return mMemoryTypeShortName[Type];
  } else {
    UnicodeSPrint (mUnknownStr, sizeof (mUnknownStr), L"%08x", Type);
    return mUnknownStr;
  }
}

/**
  Get EFI memory map information.

  @param[in] None
**/
VOID
RecordMemoryMap (
  VOID
  )
{
  EFI_STATUS             Status;
  UINTN                  MapKey;
  UINTN                  MemoryMapSize;
  EFI_MEMORY_DESCRIPTOR  *MemoryMap;
  UINTN                  DescriptorSize;
  UINT32                 DescriptorVersion;

  MemoryMapSize = 0;
  MemoryMap     = NULL;
  Status        = gBS->GetMemoryMap (
                         &MemoryMapSize,
                         MemoryMap,
                         &MapKey,
                         &DescriptorSize,
                         &DescriptorVersion
                         );
  ASSERT (Status == EFI_BUFFER_TOO_SMALL);

  do {
    Status = gBS->AllocatePool (EfiBootServicesData, MemoryMapSize, (VOID **)&MemoryMap);
    ASSERT (MemoryMap != NULL);

    Status = gBS->GetMemoryMap (
                    &MemoryMapSize,
                    MemoryMap,
                    &MapKey,
                    &DescriptorSize,
                    &DescriptorVersion
                    );
    if (EFI_ERROR (Status)) {
      gBS->FreePool (MemoryMap);
    }
  } while (Status == EFI_BUFFER_TOO_SMALL);

  mMemoryMap      = MemoryMap;
  mMemoryMapSize  = MemoryMapSize;
  mDescriptorSize = DescriptorSize;
}

/**
  Find the address memory type from EFI memory map.

  @param[in] Address         The address to map the memory type
**/
EFI_MEMORY_TYPE
GetMemoryTypeFromAddress (
  IN UINT64  Address
  )
{
  UINTN                  MemoryMapSize;
  EFI_MEMORY_DESCRIPTOR  *MemoryMap;
  UINTN                  MemoryMapEntryCount;
  UINTN                  DescriptorSize;
  UINTN                  Index;

  MemoryMap           = mMemoryMap;
  MemoryMapSize       = mMemoryMapSize;
  DescriptorSize      = mDescriptorSize;
  MemoryMapEntryCount = MemoryMapSize / DescriptorSize;
  for (Index = 0; Index < MemoryMapEntryCount; Index++) {
    if ((Address >= MemoryMap->PhysicalStart) &&
        (Address < MemoryMap->PhysicalStart + LShiftU64 (MemoryMap->NumberOfPages, EFI_PAGE_SHIFT)))
    {
      return MemoryMap->Type;
    }

    MemoryMap = NEXT_MEMORY_DESCRIPTOR (MemoryMap, DescriptorSize);
  }

  //
  // Otherwise assume MMIO
  //
  return EfiMemoryMappedIO;
}

/**
  Dump SMM Profile header.

  @param[in] SmmProfileHeader         The pointer to SMM Profile header
**/
VOID
DumpSmmProfileHeader (
  IN SMM_PROFILE_HEADER  *SmmProfileHeader
  )
{
  Print (L"  HeaderSize     - 0x%016lx\n", SmmProfileHeader->HeaderSize);
  Print (L"  MaxDataEntries - 0x%016lx\n", SmmProfileHeader->MaxDataEntries);
  Print (L"  MaxDataSize    - 0x%016lx\n", SmmProfileHeader->MaxDataSize);
  Print (L"  CurDataEntries - 0x%016lx\n", SmmProfileHeader->CurDataEntries);
  Print (L"  CurDataSize    - 0x%016lx\n", SmmProfileHeader->CurDataSize);
  Print (L"  TsegStart      - 0x%016lx\n", SmmProfileHeader->TsegStart);
  Print (L"  TsegSize       - 0x%016lx\n", SmmProfileHeader->TsegSize);
  Print (L"  NumSmis        - 0x%016lx\n", SmmProfileHeader->NumSmis);
  Print (L"  NumCpus        - 0x%016lx\n", SmmProfileHeader->NumCpus);
}

/**
  Return if the Address is the NonMmram logging Address.

  @param[in] Address the address to be checked

  @return TRUE  The address is the NonMmram logging Address.
  @return FALSE The address is not the NonMmram logging Address.
**/
BOOLEAN
IsNonMmramLoggingAddress (
  IN UINT64  Address
  )
{
  UINTN  Index;

  for (Index = 0; Index < mRescHobCount; Index++) {
    if ((Address >= mRescHob[Index].PhysicalStart) && (Address < mRescHob[Index].PhysicalStart + mRescHob[Index].ResourceLength)) {
      if ((mRescHob[Index].ResourceAttribute & MM_RESOURCE_ATTRIBUTE_LOGGING) != 0) {
        return TRUE;
      }

      return FALSE;
    }
  }

  return FALSE;
}

/**
  Dump SMM resource hob list.

  @param[in] None
**/
VOID
DumpSmmRescHobInformation (
  VOID
  )
{
  UINTN  Index;

  Print (L"SMM_HOB_RESOURCE_DESCRIPTOR\n");
  for (Index = 0; Index < (UINTN)mRescHobCount; Index++) {
    Print (
      L"Owner %g ResourceType %x ResourceAttribute 0x%016lx PhysicalStart 0x%016lx PhysicalEnd 0x%016lx ResourceLength 0x%016lx \n",
      mRescHob[Index].Owner,
      mRescHob[Index].ResourceType,
      mRescHob[Index].ResourceAttribute,
      mRescHob[Index].PhysicalStart,
      mRescHob[Index].PhysicalStart + mRescHob[Index].ResourceLength - 1,
      mRescHob[Index].ResourceLength
      );
  }

  Print (L"\n");
}

/**
  Dump all SMM Profile entry.

  @param[in] SmmProfileEntry         The entry pointer to SMM Profile.
**/
VOID
DumpSmmProfileEntry (
  IN SMM_PROFILE_ENTRY  *SmmProfileEntry
  )
{
  CHAR8            *AsciiNameString;
  CHAR16           *NameString;
  EFI_MEMORY_TYPE  MemoryType;

  Print (L"  SmiNum         - 0x%016lx\n", SmmProfileEntry->SmiNum);
  Print (L"  CpuNum         - 0x%016lx\n", SmmProfileEntry->CpuNum);
  Print (L"  ApicId         - 0x%016lx\n", SmmProfileEntry->ApicId);
  Print (L"  ErrorCode      - 0x%016lx\n", SmmProfileEntry->ErrorCode);
  Print (L"  Instruction    - 0x%016lx", SmmProfileEntry->Instruction);
  AsciiNameString = AddressToImageName ((UINTN)SmmProfileEntry->Instruction);
  if (AsciiNameString != NULL) {
    Print (L" (%a)", AsciiNameString);
  }

  Print (L"\n");
  Print (L"  Address        - 0x%016lx", SmmProfileEntry->Address);
  MemoryType = GetMemoryTypeFromAddress (SmmProfileEntry->Address);
  NameString = ShortNameOfMemoryType (MemoryType);
  if (NameString != NULL) {
    Print (L" (%s)", NameString);
  }

  Print (L"\n");
  Print (L"  SmiCmd         - 0x%016lx\n", SmmProfileEntry->SmiCmd);
}

/**
  Dump SMM Profile Data information.

  @param[in] None
**/
VOID
DumpSmmProfileInformation (
  VOID
  )
{
  SMM_PROFILE_ENTRY  *SmmProfileEntry;
  UINTN              Index;

  Print (L"SMM_PROFILE_HEADER\n");
  DumpSmmProfileHeader (mSmmProfileBase);
  SmmProfileEntry = (SMM_PROFILE_ENTRY *)(UINTN)(mSmmProfileBase + 1);

  for (Index = 0; Index < (UINTN)mSmmProfileBase->CurDataEntries; Index++) {
    Print (L"SMM_PROFILE_ENTRY[%d]\n", Index);
    DumpSmmProfileEntry (&SmmProfileEntry[Index]);
  }
}

/**
  Send SMM communication to SMM driver with function request and optional test cases.

  @param[in] SmmCommFunction         The function request to SMM driver
  @param[in] AddrAccess              Only required by the RequestAddrAccess, others set to NULL
**/
EFI_STATUS
EFIAPI
SmmCommFunctions (
  IN          SMM_PROFILE_TEST_COMM_FUNC  SmmCommFunction,
  IN OPTIONAL VOID                        *AddrAccess
  )
{
  EFI_STATUS                               Status;
  EFI_MM_COMMUNICATION_PROTOCOL            *MmCommunication;
  EDKII_PI_SMM_COMMUNICATION_REGION_TABLE  *PiSmmCommunicationRegionTable;
  EFI_MEMORY_DESCRIPTOR                    *MmCommMemRegion;
  EFI_MM_COMMUNICATE_HEADER                *CommHeader;
  SMM_PROFILE_TEST_COMM_IMAGE_DATA         *CommImage;
  SMM_PROFILE_TEST_COMM_RESCHOB_DATA       *CommRescHob;
  SMM_PROFILE_TEST_COMM_STRUCT             *CommStruct;
  UINTN                                    CommBufferSize;
  UINTN                                    Index;

  CommBufferSize = OFFSET_OF (EFI_MM_COMMUNICATE_HEADER, Data) + sizeof (SMM_PROFILE_TEST_COMM_STRUCT);

  //
  // Step 1: Grab the common buffer header.
  //
  Status = EfiGetSystemConfigurationTable (&gEdkiiPiSmmCommunicationRegionTableGuid, (VOID **)&PiSmmCommunicationRegionTable);
  if (EFI_ERROR (Status)) {
    Print (L"%a - Failed to locate SMM communciation common buffer - %r!\n", __FUNCTION__, Status);
    return Status;
  }

  //
  // Step 2: Grab one that is large enough to hold.
  //
  MmCommMemRegion = (EFI_MEMORY_DESCRIPTOR *)(PiSmmCommunicationRegionTable + 1);
  for (Index = 0; Index < PiSmmCommunicationRegionTable->NumberOfEntries; Index++) {
    if (MmCommMemRegion->Type == EfiConventionalMemory) {
      if (EFI_PAGES_TO_SIZE ((UINTN)MmCommMemRegion->NumberOfPages) >= CommBufferSize) {
        break;
      }
    }

    MmCommMemRegion = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)MmCommMemRegion + PiSmmCommunicationRegionTable->DescriptorSize);
  }

  if (Index >= PiSmmCommunicationRegionTable->NumberOfEntries) {
    Print (L"%a - Could not find a common buffer that is big enough for data!\n", __FUNCTION__);
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Step3: Start to populate contents.
  //
  CommHeader = (EFI_MM_COMMUNICATE_HEADER *)(UINTN)MmCommMemRegion->PhysicalStart;
  ZeroMem (CommHeader, CommBufferSize);
  CopyGuid (&CommHeader->HeaderGuid, &gSmmProfileTestHobGuid);
  CommHeader->MessageLength = sizeof (SMM_PROFILE_TEST_COMM_STRUCT);
  CommStruct                = (SMM_PROFILE_TEST_COMM_STRUCT *)(CommHeader->Data);
  CommStruct->Function      = SmmCommFunction;
  if (SmmCommFunction == RequestAddrAccess) {
    CopyMem (&CommStruct->CommData, AddrAccess, sizeof (SMM_PROFILE_TEST_COMM_ADDR_ACCESS_DATA));
  }

  //
  // Step 4: Locate the protocol and signal SMI.
  //
  Status = gBS->LocateProtocol (&gEfiMmCommunicationProtocolGuid, NULL, (VOID **)&MmCommunication);
  if (!EFI_ERROR (Status)) {
    Status = MmCommunication->Communicate (MmCommunication, CommHeader, &CommBufferSize);
  } else {
    Print (L"%a - Failed to locate MmCommunication protocol - %r\n", __FUNCTION__, Status);
    return Status;
  }

  //
  // Step 5: check If everything goes well.
  //
  if (EFI_ERROR (CommStruct->ReturnStatus)) {
    return (EFI_STATUS)CommStruct->ReturnStatus;
  }

  //
  // Step 6: save result.
  //
  switch (SmmCommFunction) {
    case GetImageStruct:
      CommImage            = (SMM_PROFILE_TEST_COMM_IMAGE_DATA *)CommStruct->CommData;
      mImageStructCountMax = CommImage->ImageStructCountMax;
      ASSERT (mImageStructCountMax <= MAX_NUM_OF_IMAGE_STRUCT);
      CopyMem (&mImageStruct, &CommImage->ImageStruct, mImageStructCountMax * sizeof (IMAGE_STRUCT));
      break;
    case GetRescHob:
      CommRescHob   = (SMM_PROFILE_TEST_COMM_RESCHOB_DATA *)CommStruct->CommData;
      mRescHobCount = CommRescHob->RescHobCount;
      ASSERT (mRescHobCount <= MAX_NUM_OF_RESCHOB_STRUCT);
      CopyMem (&mRescHob, &CommRescHob->RescHob, mRescHobCount * sizeof (EFI_HOB_RESOURCE_DESCRIPTOR));
      break;
  }

  return Status;
}

/**
  Get SMM Profile Data variables.

  @param[in] None
**/
EFI_STATUS
EFIAPI
GetSmmProfileVariable (
  VOID
  )
{
  EFI_STATUS  Status;
  UINTN       SmmProfileSize;

  SmmProfileSize = sizeof (mSmmProfileBase);
  Status         = gRT->GetVariable (
                          SMM_PROFILE_NAME,
                          &mSmmProfileGuid,
                          NULL,
                          &SmmProfileSize,
                          &mSmmProfileBase
                          );
  if (EFI_ERROR (Status)) {
    Print (L"SmmProfile get variable failed!\n");
    return Status;
  }

  return EFI_SUCCESS;
}

/**
  Clear SMM Profile data by CurDataEntries index.

  @param[in] None
**/
EFI_STATUS
EFIAPI
ClrSmmProfileCount (
  VOID
  )
{
  EFI_STATUS  Status;

  mSmmProfileBase->CurDataEntries = 0;
  mSmmProfileBase->CurDataSize    = 0;
  Status                          = gRT->SetVariable (
                                           SMM_PROFILE_NAME,
                                           &mSmmProfileGuid,
                                           EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
                                           sizeof (mSmmProfileBase),
                                           &mSmmProfileBase
                                           );
  if (EFI_ERROR (Status)) {
    Print (L"SmmProfile set variable failed!\n");
    return Status;
  }

  Print (L"Successfully clear SmmProfile data.\n");
  return EFI_SUCCESS;
}

/**
  The routine returns TRUE when CPU supports it (CPUID[7,0].ECX.BIT[16] is set) and
  the max physical address bits is bigger than 48. Because 4-level paging can support
  to address physical address up to 2^48 - 1, there is no need to enable 5-level paging
  with max physical address bits <= 48.

  @retval TRUE  5-level paging enabling is needed.
  @retval FALSE 5-level paging enabling is not needed.
**/
BOOLEAN
MmIplIs5LevelPagingNeeded (
  VOID
  )
{
  CPUID_VIR_PHY_ADDRESS_SIZE_EAX               VirPhyAddressSize;
  CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS_ECX  ExtFeatureEcx;
  UINT32                                       MaxExtendedFunctionId;

  AsmCpuid (CPUID_EXTENDED_FUNCTION, &MaxExtendedFunctionId, NULL, NULL, NULL);
  if (MaxExtendedFunctionId >= CPUID_VIR_PHY_ADDRESS_SIZE) {
    AsmCpuid (CPUID_VIR_PHY_ADDRESS_SIZE, &VirPhyAddressSize.Uint32, NULL, NULL, NULL);
  } else {
    VirPhyAddressSize.Bits.PhysicalAddressBits = 36;
  }

  AsmCpuidEx (
    CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS,
    CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS_SUB_LEAF_INFO,
    NULL,
    NULL,
    &ExtFeatureEcx.Uint32,
    NULL
    );

  if ((VirPhyAddressSize.Bits.PhysicalAddressBits > 4 * 9 + 12) &&
      (ExtFeatureEcx.Bits.FiveLevelPage == 1))
  {
    return TRUE;
  } else {
    return FALSE;
  }
}

/**
  Calculate the maximum support address.

  @return the maximum support address.
**/
UINT8
MmIplCalculateMaximumSupportAddress (
  VOID
  )
{
  UINT32  RegEax;
  UINT8   PhysicalAddressBits;
  VOID    *Hob;

  //
  // Get physical address bits supported.
  //
  Hob = GetFirstHob (EFI_HOB_TYPE_CPU);
  if (Hob != NULL) {
    PhysicalAddressBits = ((EFI_HOB_CPU *)Hob)->SizeOfMemorySpace;
  } else {
    AsmCpuid (CPUID_EXTENDED_FUNCTION, &RegEax, NULL, NULL, NULL);
    if (RegEax >= CPUID_VIR_PHY_ADDRESS_SIZE) {
      AsmCpuid (CPUID_VIR_PHY_ADDRESS_SIZE, &RegEax, NULL, NULL, NULL);
      PhysicalAddressBits = (UINT8)RegEax;
    } else {
      PhysicalAddressBits = 36;
    }
  }

  //
  // 4-level paging supports translating 48-bit linear addresses to 52-bit physical addresses.
  // Since linear addresses are sign-extended, the linear-address space of 4-level paging is:
  // [0, 2^47-1] and [0xffff8000_00000000, 0xffffffff_ffffffff].
  // So only [0, 2^47-1] linear-address range maps to the identical physical-address range when
  // 5-Level paging is disabled.
  //
  ASSERT (PhysicalAddressBits <= 52);
  if (!MmIplIs5LevelPagingNeeded () && (PhysicalAddressBits > 47)) {
    PhysicalAddressBits = 47;
  }

  return PhysicalAddressBits;
}

/**
  Entry point for SmmProfileTest App

  @param[in] ImageHandle          Standard entry point parameter.
  @param[in] SystemTable          Standard entry point parameter.

  @retval EFI_SUCCESS             Successfully completed.
  @retval EFI_ABORTED             InitializeHiiPackage aborted.
  @retval Others                  Status code returned by Shell functions.
**/
EFI_STATUS
EFIAPI
SmmProfileTestEntrypoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                              Status;
  LIST_ENTRY                              *ParamPackage = NULL;
  CONST CHAR16                            *ParamStartAddress;
  CONST CHAR16                            *ParamStopAddress;
  CONST CHAR16                            *ParamIntervalSize;
  SMM_PROFILE_TEST_COMM_ADDR_ACCESS_DATA  AddrAccess;
  UINTN                                   Index;
  SMM_PROFILE_ENTRY                       *SmmProfileEntry;
  UINT64                                  TestAddress;
  BOOLEAN                                 FoundMatchEntry;
  UINT64                                  MaxAddress;

  //
  // Initialize the shell lib
  //
  Status = ShellInitialize ();
  ASSERT_EFI_ERROR (Status);

  mSmmProfileTestHiiHandle = InitializeHiiPackage (ImageHandle);
  if (mSmmProfileTestHiiHandle == NULL) {
    return EFI_ABORTED;
  }

  RecordMemoryMap ();
  Status = GetSmmProfileVariable ();
  if (EFI_ERROR (Status)) {
    Print (L"GetSmmProfileVariable failed!\n");
    goto SmmProfileTestExit;
  }

  ZeroMem (&AddrAccess, sizeof (AddrAccess));

  //
  // Process Command Line arguments
  //
  Status = ShellCommandLineParse (ParamList, &ParamPackage, NULL, TRUE);
  if (EFI_ERROR (Status)) {
    Print (L"SmmProfileTest: Invalid parameters!\n");
    Status = SHELL_INVALID_PARAMETER;
    goto SmmProfileTestExit;
  }

  if (ShellCommandLineGetFlag (ParamPackage, L"-dump")) {
    Status = SmmCommFunctions (GetImageStruct, NULL);
    if (EFI_ERROR (Status)) {
      Print (L"SmmProfile GetImageStruct failed!\n");
      goto SmmProfileTestExit;
    }

    DumpSmmProfileInformation ();
  } else if (ShellCommandLineGetFlag (ParamPackage, L"-clr")) {
    Status = ClrSmmProfileCount ();
    if (EFI_ERROR (Status)) {
      Print (L"SmmProfile ClrSmmProfileCount failed!\n");
    }
  } else if (ShellCommandLineGetFlag (ParamPackage, L"-mmreschob")) {
    Status = SmmCommFunctions (GetRescHob, NULL);
    if (EFI_ERROR (Status)) {
      Print (L"SmmProfile GetRescHob failed!\n");
      goto SmmProfileTestExit;
    }

    DumpSmmRescHobInformation ();
  } else if (ShellCommandLineGetFlag (ParamPackage, L"-test")) {
    //
    // Get input parameters (or default) into AddrAccess
    //
    ParamStartAddress = ShellCommandLineGetValue (ParamPackage, L"-StartAddress");
    if (ParamStartAddress == NULL) {
      Print (L"Invalid parameter - No StartAddress!\n");
      goto SmmProfileTestExit;
    }

    Status = ShellConvertStringToUint64 (ParamStartAddress, &AddrAccess.StartAddress, TRUE, TRUE);
    if (EFI_ERROR (Status)) {
      Print (L"Invalid parameter - Incorrect of StartAddress format!\n");
      goto SmmProfileTestExit;
    }

    ParamStopAddress = ShellCommandLineGetValue (ParamPackage, L"-StopAddress");
    if (ParamStopAddress == NULL) {
      // Set default StopAddress to StartAddress
      ParamStopAddress = ParamStartAddress;
    }

    Status = ShellConvertStringToUint64 (ParamStopAddress, &AddrAccess.StopAddress, TRUE, TRUE);
    if (EFI_ERROR (Status)) {
      Print (L"Invalid parameter - Incorrect of StopAddress format!\n");
      goto SmmProfileTestExit;
    }

    ParamIntervalSize = ShellCommandLineGetValue (ParamPackage, L"-IntervalSize");
    if (ParamIntervalSize == NULL) {
      // Set default IntervalSize to 2MB
      ParamIntervalSize = L"200000";
    }

    Status = ShellConvertStringToUint64 (ParamIntervalSize, &AddrAccess.IntervalSize, TRUE, TRUE);
    if (EFI_ERROR (Status)) {
      Print (L"Invalid parameter - Incorrect of IntervalSize format!\n");
      goto SmmProfileTestExit;
    }

    //
    // Get system end address
    //
    MaxAddress = LShiftU64 (1, MmIplCalculateMaximumSupportAddress ());

    //
    // Validate StartAddress input parameter
    //
    if (AddrAccess.StartAddress < 0x1000) {
      Print (L"SmmProfileTestCase not allow NULL address 0x%016lx!\n", AddrAccess.StartAddress);
      goto SmmProfileTestExit;
    }

    if (AddrAccess.StartAddress >= MaxAddress) {
      Print (L"SmmProfileTestCase StartAddress cannot be larger than end address 0x%016lx!\n", MaxAddress);
      goto SmmProfileTestExit;
    }

    //
    // Validate StopAddress input parameter
    //
    if (AddrAccess.StopAddress < AddrAccess.StartAddress) {
      Print (L"SmmProfileTestCase StopAddress cannot be smaller than StartAddress!\n");
      goto SmmProfileTestExit;
    }

    if (AddrAccess.StopAddress >= MaxAddress) {
      Print (L"SmmProfileTestCase StopAddress cannot be larger than end address 0x%016lx!\n", MaxAddress);
      goto SmmProfileTestExit;
    }

    //
    // Validate IntervalSize input parameter
    //
    if (AddrAccess.IntervalSize < SIZE_2MB) {
      Print (L"SmmProfileTestCase IntervalSize cannot be smaller than 2MB!\n");
      goto SmmProfileTestExit;
    }

    //
    // Clear SMM Profile count before run test
    //
    Status = ClrSmmProfileCount ();
    if (EFI_ERROR (Status)) {
      Print (L"SmmProfile ClrSmmProfileCount failed!\n");
    }

    //
    // Run test
    //
    Status = SmmCommFunctions (RequestAddrAccess, (VOID *)&AddrAccess);
    if (EFI_ERROR (Status)) {
      Print (L"SmmProfile RequestAddrAccess failed!\n");
      return Status;
    }

    //
    // Verification againts MM_RESOURCE_ATTRIBUTE_LOGGING and SMM_PROFILE_ENTRY
    //
    Status = SmmCommFunctions (GetRescHob, NULL);
    if (EFI_ERROR (Status)) {
      Print (L"SmmProfile GetRescHob failed!\n");
      goto SmmProfileTestExit;
    }

    SmmProfileEntry = (SMM_PROFILE_ENTRY *)(UINTN)(mSmmProfileBase + 1);

    //
    // Check requested addresses
    //
    for (TestAddress = AddrAccess.StartAddress; TestAddress <= AddrAccess.StopAddress; TestAddress += AddrAccess.IntervalSize) {
      FoundMatchEntry = FALSE;
      for (Index = 0; Index < (UINTN)mSmmProfileBase->CurDataEntries; Index++) {
        if (SmmProfileEntry[Index].Address == TestAddress) {
          FoundMatchEntry = TRUE;
          break;
        }
      }

      if (IsNonMmramLoggingAddress (TestAddress)) {
        if (FoundMatchEntry == FALSE) {
          Print (L"SmmProfileTestCase ===> Fail Address[0x%016lx] Test. It is logging address, but not recorded in SmmProfileEntry!\n", TestAddress);
        } else {
          Print (L"SmmProfileTestCase ===> Pass Address[0x%016lx] Test. It is logging address and recorded at SmmProfileEntry[%d] successfully.\n", TestAddress, Index);
        }
      } else {
        if (FoundMatchEntry == FALSE) {
          Print (L"SmmProfileTestCase ===> Pass Address[0x%016lx] Test. It is non-logging address and not recorded in SmmProfileEntry.\n", TestAddress);
        } else {
          Print (L"SmmProfileTestCase ===> Fail Address[0x%016lx] Test. It is non-logging address, but recorded at SmmProfileEntry[%d]!\n", TestAddress, Index);
        }
      }
    }

    //
    // Check unknown addresses
    //
    for (Index = 0; Index < (UINTN)mSmmProfileBase->CurDataEntries; Index++) {
      FoundMatchEntry = FALSE;
      for (TestAddress = AddrAccess.StartAddress; TestAddress <= AddrAccess.StopAddress; TestAddress += AddrAccess.IntervalSize) {
        if (SmmProfileEntry[Index].Address == TestAddress) {
          FoundMatchEntry = TRUE;
          break;
        }
      }

      if (FoundMatchEntry == FALSE) {
        if (IsNonMmramLoggingAddress (SmmProfileEntry[Index].Address)) {
          Print (L"SmmProfileTestCase ===> Unknown Address[0x%016lx]. It is logging address and recorded at SmmProfileEntry[%d]!\n", SmmProfileEntry[Index].Address, Index);
        } else {
          Print (L"SmmProfileTestCase ===> Unknown Address[0x%016lx]. It is non-logging address, but recorded at SmmProfileEntry[%d]!\n", SmmProfileEntry[Index].Address, Index);
        }
      }
    }
  } else {
    //
    // None/Invalid function parameters
    //
    ShellPrintHiiEx (-1, -1, NULL, STRING_TOKEN (STR_GET_HELP_SMMPROFILETEST), mSmmProfileTestHiiHandle);
    Status = EFI_SUCCESS;
    goto SmmProfileTestExit;
  }

SmmProfileTestExit:
  if (mMemoryMap != NULL) {
    FreePool (mMemoryMap);
  }

  if (ParamPackage != NULL) {
    ShellCommandLineFreeVarList (ParamPackage);
  }

  if (mSmmProfileTestHiiHandle != NULL) {
    HiiRemovePackages (mSmmProfileTestHiiHandle);
  }

  return Status;
}
