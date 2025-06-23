/** @file

**/

#include "TlsImpl.h"

EFI_SERVICE_BINDING_PROTOCOL  mTlsServiceBinding = {
  TlsServiceBindingCreateChild,
  TlsServiceBindingDestroyChild
};

/**
  Release all the resource used the TLS instance.

  @param  Instance        The TLS instance data.

**/
VOID
TlsCleanInstance (
  IN TLS_INSTANCE  *Instance
  )
{
  if (Instance != NULL) {
    if (Instance->TlsCipher != NULL) {
      FreePool (Instance->TlsCipher);
    }

    if (Instance->TlsCompression != NULL) {
      FreePool (Instance->TlsCompression);
    }

    if (Instance->TlsExtension != NULL) {
      FreePool (Instance->TlsExtension);
    }

    if (Instance->TlsResumeSessionID != NULL) {
      FreePool (Instance->TlsResumeSessionID);
    }

    if (Instance->TlsAlert != NULL) {
      FreePool (Instance->TlsAlert);
    }

    if (Instance->ClientCACert != NULL) {
      FreePool (Instance->ClientCACert);
    }

    if (Instance->ClientCert != NULL) {
      FreePool (Instance->ClientCert);
    }

    if (Instance->ClientPrivateKey != NULL) {
      FreePool (Instance->ClientPrivateKey);
    }

    if (Instance->TlsSessionContext.ServerRSAPubKey != NULL) {
      FreePool (Instance->TlsSessionContext.ServerRSAPubKey);
    }

    if (Instance->TlsSessionContext.ClientAesKey != NULL) {
      FreePool (Instance->TlsSessionContext.ClientAesKey);
    }

    if (Instance->TlsSessionContext.ServerAesKey != NULL) {
      FreePool (Instance->TlsSessionContext.ServerAesKey);
    }

    Instance->TlsSessionContext.ClientWriteMacSecret = NULL;
    Instance->TlsSessionContext.ServerWriteMacSecret = NULL;
    Instance->TlsSessionContext.ClientWriteKey       = NULL;
    Instance->TlsSessionContext.ServerWriteKey       = NULL;
    Instance->TlsSessionContext.ClientWriteIv        = NULL;
    Instance->TlsSessionContext.ServerWriteIv        = NULL;

    FreePool (Instance);
  }
}

/**
  Create the TLS instance and initialize it.

  @param[in]  Service              The pointer to the TLS service.
  @param[out] Instance             The pointer to the TLS instance.

  @retval EFI_OUT_OF_RESOURCES   Failed to allocate resources.
  @retval EFI_SUCCESS            The TLS instance is created.

**/
EFI_STATUS
TlsCreateInstance (
  IN  TLS_SERVICE   *Service,
  OUT TLS_INSTANCE  **Instance
  )
{
  TLS_INSTANCE  *TlsInstance;

  *Instance = NULL;

  TlsInstance = AllocateZeroPool (sizeof (TLS_INSTANCE));
  if (TlsInstance == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  TlsInstance->Signature = TLS_INSTANCE_SIGNATURE;
  InitializeListHead (&TlsInstance->Link);
  TlsInstance->State   = TLS_STATE_UNCONFIGED;
  TlsInstance->Service = Service;

  CopyMem (&TlsInstance->Tls, &mTlsProtocol, sizeof (TlsInstance->Tls));
  CopyMem (&TlsInstance->TlsConfig, &mTlsConfigurationProtocol, sizeof (TlsInstance->TlsConfig));

  TlsInstance->TlsSessionState = EfiTlsSessionNotStarted;

  *Instance = TlsInstance;

  return EFI_SUCCESS;
}

/**
  Release all the resource used the TLS service binding instance.

  @param  Service        The TLS service data.

**/
VOID
TlsCleanService (
  IN TLS_SERVICE  *Service
  )
{
  if (Service != NULL) {
    FreePool (Service);
  }
}

/**
  Create then initialize a TLS service.

  @param  Image                  ImageHandle of the TLS driver
  @param  Service                The service for TLS driver

  @retval EFI_OUT_OF_RESOURCES   Failed to allocate resource to create the service.
  @retval EFI_SUCCESS            The service is created for the driver.

**/
EFI_STATUS
TlsCreateService (
  IN     EFI_HANDLE  Image,
  OUT TLS_SERVICE    **Service
  )
{
  EFI_STATUS   Status;
  TLS_SERVICE  *TlsService;

  Status = EFI_SUCCESS;

  ASSERT (Service != NULL);

  *Service = NULL;

  TlsService = AllocateZeroPool (sizeof (TLS_SERVICE));
  if (TlsService == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  TlsService->Signature = TLS_SERVICE_SIGNATURE;
  CopyMem (&TlsService->ServiceBinding, &mTlsServiceBinding, sizeof (TlsService->ServiceBinding));
  TlsService->TlsChildrenNum = 0;
  InitializeListHead (&TlsService->TlsChildrenList);
  TlsService->ImageHandle = Image;

  *Service = TlsService;

  return Status;
}

/**
  Unloads an image.

  @param  ImageHandle           Handle that identifies the image to be unloaded.

  @retval EFI_SUCCESS           The image has been unloaded.
  @retval EFI_INVALID_PARAMETER ImageHandle is not a valid image handle.

**/
EFI_STATUS
EFIAPI
TlsUnload (
  IN EFI_HANDLE  ImageHandle
  )
{
  EFI_STATUS                    Status;
  UINTN                         HandleNum;
  EFI_HANDLE                    *HandleBuffer;
  UINT32                        Index;
  EFI_SERVICE_BINDING_PROTOCOL  *ServiceBinding;
  TLS_SERVICE                   *TlsService;

  HandleBuffer   = NULL;
  ServiceBinding = NULL;
  TlsService     = NULL;

  //
  // Locate all the handles with Tls service binding protocol.
  //
  Status = gBS->LocateHandleBuffer (
                                    ByProtocol,
                                    &gEfiTlsServiceBindingProtocolGuid,
                                    NULL,
                                    &HandleNum,
                                    &HandleBuffer
                                    );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  for (Index = 0; Index < HandleNum; Index++) {
    //
    // Firstly, find ServiceBinding interface
    //
    Status = gBS->OpenProtocol (
                                HandleBuffer[Index],
                                &gEfiTlsServiceBindingProtocolGuid,
                                (VOID **)&ServiceBinding,
                                ImageHandle,
                                NULL,
                                EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL
                                );
    if (EFI_ERROR (Status)) {
      return Status;
    }

    TlsService = TLS_SERVICE_FROM_THIS (ServiceBinding);

    //
    // Then, uninstall ServiceBinding interface
    //
    Status = gBS->UninstallMultipleProtocolInterfaces (
                                                       HandleBuffer[Index],
                                                       &gEfiTlsServiceBindingProtocolGuid,
                                                       ServiceBinding,
                                                       NULL
                                                       );
    if (EFI_ERROR (Status)) {
      return Status;
    }

    TlsCleanService (TlsService);
  }

  return EFI_SUCCESS;
}

/**
  This is the declaration of an EFI image entry point. This entry point is
  the same for UEFI Applications, UEFI OS Loaders, and UEFI Drivers including
  both device drivers and bus drivers.

  @param  ImageHandle           The firmware allocated handle for the UEFI image.
  @param  SystemTable           A pointer to the EFI System Table.

  @retval EFI_SUCCESS           The operation completed successfully.
  @retval Others                An unexpected error occurred.
**/
EFI_STATUS
EFIAPI
TlsDriverEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  TLS_SERVICE  *TlsService;

  //
  // Create TLS Service
  //
  Status = TlsCreateService (ImageHandle, &TlsService);
  if (EFI_ERROR (Status)) {
    goto ON_ERROR;
  }

  ASSERT (TlsService != NULL);

  //
  // Install the TlsServiceBinding Protocol onto Handle
  //
  Status = gBS->InstallMultipleProtocolInterfaces (
                                                   &TlsService->Handle,
                                                   &gEfiTlsServiceBindingProtocolGuid,
                                                   &TlsService->ServiceBinding,
                                                   NULL
                                                   );
  if (EFI_ERROR (Status)) {
    goto ON_CLEAN_SERVICE;
  }

  return Status;

ON_CLEAN_SERVICE:
  TlsCleanService (TlsService);
ON_ERROR:
  return Status;
}

/**
  Creates a child handle and installs a protocol.

  The CreateChild() function installs a protocol on ChildHandle.
  If ChildHandle is a pointer to NULL, then a new handle is created and returned in ChildHandle.
  If ChildHandle is not a pointer to NULL, then the protocol installs on the existing ChildHandle.

  @param[in] This        Pointer to the EFI_SERVICE_BINDING_PROTOCOL instance.
  @param[in] ChildHandle Pointer to the handle of the child to create. If it is NULL,
                         then a new handle is created. If it is a pointer to an existing UEFI handle,
                         then the protocol is added to the existing UEFI handle.

  @retval EFI_SUCCES            The protocol was added to ChildHandle.
  @retval EFI_INVALID_PARAMETER ChildHandle is NULL.
  @retval EFI_OUT_OF_RESOURCES  There are not enough resources availabe to create
                                the child
  @retval other                 The child handle was not created

**/
EFI_STATUS
EFIAPI
TlsServiceBindingCreateChild (
  IN EFI_SERVICE_BINDING_PROTOCOL  *This,
  IN EFI_HANDLE                    *ChildHandle
  )
{
  TLS_SERVICE   *TlsService;
  TLS_INSTANCE  *TlsInstance;
  EFI_STATUS    Status;
  EFI_TPL       OldTpl;

  if ((This == NULL) || (ChildHandle == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  TlsService = TLS_SERVICE_FROM_THIS (This);

  Status = TlsCreateInstance (TlsService, &TlsInstance);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  ASSERT (TlsInstance != NULL);

  //
  // Install TLS protocol and configuration protocol onto ChildHandle
  //
  Status = gBS->InstallMultipleProtocolInterfaces (
                                                   ChildHandle,
                                                   &gEfiTlsProtocolGuid,
                                                   &TlsInstance->Tls,
                                                   &gEfiTlsConfigurationProtocolGuid,
                                                   &TlsInstance->TlsConfig,
                                                   NULL
                                                   );
  if (EFI_ERROR (Status)) {
    goto ON_ERROR;
  }

  TlsInstance->ChildHandle = *ChildHandle;

  //
  // Add it to the TLS service's child list.
  //
  OldTpl = gBS->RaiseTPL (TPL_CALLBACK);

  InsertTailList (&TlsService->TlsChildrenList, &TlsInstance->Link);
  TlsService->TlsChildrenNum++;

  gBS->RestoreTPL (OldTpl);

  return EFI_SUCCESS;

ON_ERROR:
  TlsCleanInstance (TlsInstance);

  return Status;
}

/**
  Destroys a child handle with a protocol installed on it.

  The DestroyChild() function does the opposite of CreateChild(). It removes a protocol
  that was installed by CreateChild() from ChildHandle. If the removed protocol is the
  last protocol on ChildHandle, then ChildHandle is destroyed.

  @param  This        Pointer to the EFI_SERVICE_BINDING_PROTOCOL instance.
  @param  ChildHandle Handle of the child to destroy

  @retval EFI_SUCCES            The protocol was removed from ChildHandle.
  @retval EFI_UNSUPPORTED       ChildHandle does not support the protocol that is being removed.
  @retval EFI_INVALID_PARAMETER Child handle is NULL.
  @retval EFI_ACCESS_DENIED     The protocol could not be removed from the ChildHandle
                                because its services are being used.
  @retval other                 The child handle was not destroyed

**/
EFI_STATUS
EFIAPI
TlsServiceBindingDestroyChild (
  IN EFI_SERVICE_BINDING_PROTOCOL  *This,
  IN EFI_HANDLE                    ChildHandle
  )
{
  TLS_SERVICE   *TlsService;
  TLS_INSTANCE  *TlsInstance;

  EFI_TLS_PROTOCOL                *Tls;
  EFI_TLS_CONFIGURATION_PROTOCOL  *TlsConfig;
  EFI_STATUS                      Status;
  EFI_TPL                         OldTpl;

  if ((This == NULL) || (ChildHandle == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  TlsService = TLS_SERVICE_FROM_THIS (This);

  //
  // Find TLS protocol interface installed in ChildHandle
  //
  Status = gBS->OpenProtocol (
                              ChildHandle,
                              &gEfiTlsProtocolGuid,
                              (VOID **)&Tls,
                              TlsService->ImageHandle,
                              NULL,
                              EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL
                              );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Find TLS configuration protocol interface installed in ChildHandle
  //
  Status = gBS->OpenProtocol (
                              ChildHandle,
                              &gEfiTlsConfigurationProtocolGuid,
                              (VOID **)&TlsConfig,
                              TlsService->ImageHandle,
                              NULL,
                              EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL
                              );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  TlsInstance = TLS_INSTANCE_FROM_PROTOCOL_THIS (Tls);
  ASSERT (!CompareMem (TlsInstance, TLS_INSTANCE_FROM_CONFIGURATION_THIS (TlsConfig), sizeof (TLS_INSTANCE)));

  if (TlsInstance->Service != TlsService) {
    return EFI_INVALID_PARAMETER;
  }

  if (TlsInstance->State == TLS_STATE_DESTROY) {
    return EFI_SUCCESS;
  }

  //
  // Uninstall the TLS protocol and TLS Configuration Protocol interface installed in ChildHandle.
  //
  Status = gBS->UninstallMultipleProtocolInterfaces (
                                                     ChildHandle,
                                                     &gEfiTlsProtocolGuid,
                                                     Tls,
                                                     &gEfiTlsConfigurationProtocolGuid,
                                                     TlsConfig,
                                                     NULL
                                                     );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  OldTpl = gBS->RaiseTPL (TPL_CALLBACK);

  TlsInstance->State = TLS_STATE_DESTROY;

  RemoveEntryList (&TlsInstance->Link);
  TlsService->TlsChildrenNum--;

  gBS->RestoreTPL (OldTpl);

  TlsCleanInstance (TlsInstance);

  return EFI_SUCCESS;
}
