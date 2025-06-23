/** @file

  Copyright (c) 2025, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SmmProfileTestStandaloneMm.h"

EFI_HANDLE  mSmmProfileTestHandle = NULL;

CHAR16  mNameString[MAX_LENGTH_OF_PDB_STRING + 1];

UINTN  mImageStructCount;
UINTN  mImageStructCountMax;

VOID
AddImageStruct (
  IN OUT SMM_PROFILE_TEST_COMM_IMAGE_DATA  *CommImage,
  IN PHYSICAL_ADDRESS                      ImageBase,
  IN UINT64                                ImageSize,
  IN PHYSICAL_ADDRESS                      LoadedImageBase,
  IN PHYSICAL_ADDRESS                      EntryPoint,
  IN CHAR8                                 *PdbString,
  IN EFI_GUID                              *Guid
  )
{
  UINTN         PdbStringInit;
  UINTN         PdbStringSize;
  IMAGE_STRUCT  *ImageStruct;

  if (mImageStructCount >= mImageStructCountMax) {
    ASSERT (FALSE);
    return;
  }

  ImageStruct = CommImage->ImageStruct;

  CopyGuid (&ImageStruct[mImageStructCount].FileGuid, Guid);
  ImageStruct[mImageStructCount].ImageBase       = ImageBase;
  ImageStruct[mImageStructCount].ImageSize       = ImageSize;
  ImageStruct[mImageStructCount].LoadedImageBase = LoadedImageBase;
  ImageStruct[mImageStructCount].EntryPoint      = EntryPoint;
  if (PdbString != NULL) {
    PdbStringInit = 0;
    PdbStringSize = AsciiStrSize (PdbString);
    if (PdbStringSize > MAX_LENGTH_OF_PDB_STRING + 1) {
      PdbStringInit = PdbStringSize - MAX_LENGTH_OF_PDB_STRING;
      PdbStringSize = MAX_LENGTH_OF_PDB_STRING + 1;
    }

    AsciiStrnCpyS (ImageStruct[mImageStructCount].PdbString, MAX_LENGTH_OF_PDB_STRING + 1, PdbString+PdbStringInit, PdbStringSize);
  }

  mImageStructCount++;
}

/**
  Collect SMM image information based upon loaded image protocol.
**/
EFI_STATUS
EFIAPI
GetMmLoadedImage (
  OUT SMM_PROFILE_TEST_COMM_IMAGE_DATA  *CommImage
  )
{
  EFI_STATUS                 Status;
  UINTN                      HandleBufferSize;
  EFI_HANDLE                 *HandleBuffer;
  UINTN                      Index;
  EFI_LOADED_IMAGE_PROTOCOL  *LoadedImage;
  PHYSICAL_ADDRESS           EntryPoint;
  EFI_GUID                   Guid;
  CHAR8                      *PdbString;
  PHYSICAL_ADDRESS           RealImageBase;

  HandleBufferSize = 0;
  HandleBuffer     = NULL;
  Status           = gMmst->MmLocateHandle (
                              ByProtocol,
                              &gEfiLoadedImageProtocolGuid,
                              NULL,
                              &HandleBufferSize,
                              HandleBuffer
                              );
  if (Status != EFI_BUFFER_TOO_SMALL) {
    return Status;
  }

  HandleBuffer = AllocateZeroPool (HandleBufferSize);
  if (HandleBuffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Status = gMmst->MmLocateHandle (
                    ByProtocol,
                    &gEfiLoadedImageProtocolGuid,
                    NULL,
                    &HandleBufferSize,
                    HandleBuffer
                    );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  mImageStructCountMax           = HandleBufferSize/sizeof (EFI_HANDLE);
  CommImage->ImageStructCountMax = mImageStructCountMax;
  if (mImageStructCountMax > MAX_NUM_OF_IMAGE_STRUCT) {
    DEBUG ((DEBUG_INFO, "[%a] - Function requested CommBuff not enough\n", __FUNCTION__));
    FreePool (HandleBuffer);
    return EFI_BUFFER_TOO_SMALL;
  }

  mImageStructCount = 0;
  for (Index = 0; Index < mImageStructCountMax; Index++) {
    Status = gMmst->MmHandleProtocol (
                      HandleBuffer[Index],
                      &gEfiLoadedImageProtocolGuid,
                      (VOID **)&LoadedImage
                      );
    if (EFI_ERROR (Status)) {
      continue;
    }

    ZeroMem (&Guid, sizeof (EFI_GUID));
    EntryPoint    = 0;
    RealImageBase = (UINTN)LoadedImage->ImageBase;

    if (RealImageBase != 0) {
      PdbString = PeCoffLoaderGetPdbPointer ((VOID *)(UINTN)RealImageBase);
    } else {
      PdbString = NULL;
    }

    AddImageStruct (CommImage, RealImageBase, LoadedImage->ImageSize, (PHYSICAL_ADDRESS)LoadedImage->ImageBase, EntryPoint, PdbString, &Guid);
  }

  FreePool (HandleBuffer);
  return EFI_SUCCESS;
}

/**
  Get SMM resources hob.
**/
EFI_STATUS
EFIAPI
GetMmResourceHob (
  OUT SMM_PROFILE_TEST_COMM_RESCHOB_DATA  *CommRescHob
  )
{
  EFI_PEI_HOB_POINTERS         Hob;
  EFI_HOB_RESOURCE_DESCRIPTOR  *ResourceDescriptor;

  CommRescHob->RescHobCount = 0;
  Hob.Raw                   = GetFirstHob (EFI_HOB_TYPE_RESOURCE_DESCRIPTOR);
  while (Hob.Raw != NULL) {
    ResourceDescriptor = (EFI_HOB_RESOURCE_DESCRIPTOR *)Hob.Raw;
    CopyMem (&CommRescHob->RescHob[CommRescHob->RescHobCount], ResourceDescriptor, sizeof (EFI_HOB_RESOURCE_DESCRIPTOR));
    CommRescHob->RescHobCount++;
    Hob.Raw = GET_NEXT_HOB (Hob);
    Hob.Raw = GetNextHob (EFI_HOB_TYPE_RESOURCE_DESCRIPTOR, Hob.Raw);
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
SmmProfileTestCommunciate (
  IN     EFI_HANDLE  DispatchHandle,
  IN     CONST VOID  *RegisterContext,
  IN OUT VOID        *CommBuffer,
  IN OUT UINTN       *CommBufferSize
  )
{
  EFI_STATUS                              Status;
  UINTN                                   TempCommBufferSize;
  SMM_PROFILE_TEST_COMM_IMAGE_DATA        *CommImage;
  SMM_PROFILE_TEST_COMM_RESCHOB_DATA      *CommRescHob;
  SMM_PROFILE_TEST_COMM_ADDR_ACCESS_DATA  *AddrAccess;
  SMM_PROFILE_TEST_COMM_STRUCT            *CommStruct;
  UINT64                                  TestAddress;

  Status = EFI_SUCCESS;

  DEBUG ((DEBUG_INFO, "%a()\n", __FUNCTION__));

  //
  // If input is invalid, stop processing this SMI
  //
  if ((CommBuffer == NULL) || (CommBufferSize == NULL)) {
    return EFI_SUCCESS;
  }

  TempCommBufferSize = *CommBufferSize;

  if (TempCommBufferSize != sizeof (SMM_PROFILE_TEST_COMM_STRUCT)) {
    DEBUG ((DEBUG_ERROR, "[%a] MM Communication buffer size is invalid for this handler!\n", __FUNCTION__));
    return EFI_ACCESS_DENIED;
  }

  //
  // Farm out the job to individual functions based on what was requested.
  //
  CommStruct = (SMM_PROFILE_TEST_COMM_STRUCT *)CommBuffer;
  switch (CommStruct->Function) {
    case GetImageStruct:
      DEBUG ((DEBUG_INFO, "[%a] - Function requested: GetImageStruct\n", __FUNCTION__));
      CommImage = (SMM_PROFILE_TEST_COMM_IMAGE_DATA *)CommStruct->CommData;
      Status    = GetMmLoadedImage (CommImage);
      break;

    case GetRescHob:
      DEBUG ((DEBUG_INFO, "[%a] - Function requested: GetRescHob\n", __FUNCTION__));
      CommRescHob = (SMM_PROFILE_TEST_COMM_RESCHOB_DATA *)CommStruct->CommData;
      Status      = GetMmResourceHob (CommRescHob);
      break;

    case RequestAddrAccess:
      DEBUG ((DEBUG_INFO, "[%a] - Function requested: RequestAddrAccess\n", __FUNCTION__));
      AddrAccess = (SMM_PROFILE_TEST_COMM_ADDR_ACCESS_DATA *)CommStruct->CommData;
      for (TestAddress = AddrAccess->StartAddress; TestAddress <= AddrAccess->StopAddress; TestAddress += AddrAccess->IntervalSize) {
        DEBUG ((DEBUG_INFO, "[%a] - TestAddress: %016lx\n", __FUNCTION__, TestAddress));
        AsmReadMem64 (TestAddress);
      }

      break;

    default:
      DEBUG ((DEBUG_INFO, "[%a] - Unknown function %d!\n", __FUNCTION__, CommStruct->Function));
      Status = EFI_UNSUPPORTED;
      break;
  }

  CommStruct->ReturnStatus = (UINT64)Status;

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
SmmProfileTestStandaloneMmEntry (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_MM_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  //
  // Register a handler to communicate the SmmProfileTest data between MM and Non-MM
  //
  Status = gMmst->MmiHandlerRegister (SmmProfileTestCommunciate, &gSmmProfileTestHobGuid, &mSmmProfileTestHandle);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[%a] Failed to register handler for SmmProfileTest data- %r!\n", __FUNCTION__, Status));
  }

  DEBUG ((DEBUG_INFO, "SmmProfileTestStandaloneMmEntry, Status: %r\n", Status));

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
SmmProfileTestStandaloneMmUnload (
  IN EFI_HANDLE  ImageHandle
  )
{
  EFI_STATUS  Status;

  Status = EFI_SUCCESS;

  if (mSmmProfileTestHandle != NULL) {
    Status = gMmst->MmiHandlerUnRegister (mSmmProfileTestHandle);
  }

  DEBUG ((DEBUG_INFO, "SmmProfileTestStandaloneMmUnload, Status: %r\n", Status));
  return Status;
}
