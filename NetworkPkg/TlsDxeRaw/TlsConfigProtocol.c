/** @file

**/

#include "TlsImpl.h"

EFI_TLS_CONFIGURATION_PROTOCOL  mTlsConfigurationProtocol = {
  TlsConfigurationSetData,
  TlsConfigurationGetData
};

EFI_STATUS
EFIAPI
TlsConfigurationSetData (
  IN     EFI_TLS_CONFIGURATION_PROTOCOL  *This,
  IN     EFI_TLS_CONFIG_DATA_TYPE        DataType,
  IN     VOID                            *Data,
  IN     UINTN                           DataSize
  )
{
  EFI_STATUS    Status;
  TLS_INSTANCE  *Instance;

  EFI_TPL  OldTpl;

  Status = EFI_SUCCESS;

  if ((This == NULL) ||  (Data == NULL) || (DataSize == 0)) {
    return EFI_INVALID_PARAMETER;
  }

  OldTpl = gBS->RaiseTPL (TPL_CALLBACK);

  Instance = TLS_INSTANCE_FROM_CONFIGURATION_THIS (This);

  if (Instance->TlsSessionState != EfiTlsSessionNotStarted) {
    Status = EFI_NOT_READY;
    goto ON_EXIT;
  }

  switch (DataType) {
    case EfiTlsConfigDataTypeCACertificate:
      Instance->ClientCACert = AllocatePool (DataSize);
      if (Instance->ClientCACert == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
        goto ON_EXIT;
      }

      Instance->ClientCACertSize = DataSize;
      CopyMem (Instance->ClientCACert, Data, Instance->ClientCACertSize);
      Instance->State = TLS_STATE_CONFIGED;
      break;
    case EfiTlsConfigDataTypeHostPublicCert:
      Instance->ClientCert = AllocatePool (DataSize);
      if (Instance->ClientCert == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
        goto ON_EXIT;
      }

      Instance->ClientCertSize = DataSize;
      CopyMem (Instance->ClientCert, Data, Instance->ClientCertSize);
      Instance->State = TLS_STATE_CONFIGED;
      break;
    case EfiTlsConfigDataTypeHostPrivateKey:
      Instance->ClientPrivateKey = AllocatePool (DataSize);
      if (Instance->ClientPrivateKey == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
        goto ON_EXIT;
      }

      Instance->ClientPrivateKeySize = DataSize;
      CopyMem (Instance->ClientPrivateKey, Data, Instance->ClientPrivateKeySize);
      Instance->State = TLS_STATE_CONFIGED;
      break;
    default:
      Status = EFI_UNSUPPORTED;
      // goto ON_EXIT;
  }

ON_EXIT:
  gBS->RestoreTPL (OldTpl);
  return Status;
}

EFI_STATUS
EFIAPI
TlsConfigurationGetData (
  IN     EFI_TLS_CONFIGURATION_PROTOCOL  *This,
  IN     EFI_TLS_CONFIG_DATA_TYPE        DataType,
  IN OUT VOID                            *Data,
  IN OUT UINTN                           *DataSize
  )
{
  EFI_STATUS    Status;
  TLS_INSTANCE  *Instance;

  EFI_TPL  OldTpl;

  Status = EFI_SUCCESS;

  if ((This == NULL) ||  (Data == NULL) || (DataSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  OldTpl = gBS->RaiseTPL (TPL_CALLBACK);

  Instance = TLS_INSTANCE_FROM_CONFIGURATION_THIS (This);

  if (Instance->TlsSessionState == EfiTlsSessionNotStarted) {
    Status = EFI_NOT_READY;
    goto ON_EXIT;
  }

  switch (DataType) {
    case EfiTlsConfigDataTypeCACertificate:
      if (*DataSize < Instance->ClientCACertSize) {
        *DataSize = Instance->ClientCACertSize;
        Status    = EFI_BUFFER_TOO_SMALL;
        goto ON_EXIT;
      }

      *DataSize = Instance->ClientCACertSize;
      CopyMem (Data, Instance->ClientCACert, *DataSize);
      break;
    case EfiTlsConfigDataTypeHostPublicCert:
      if (*DataSize < Instance->ClientCertSize) {
        *DataSize = Instance->ClientCertSize;
        Status    = EFI_BUFFER_TOO_SMALL;
        goto ON_EXIT;
      }

      *DataSize = Instance->ClientCertSize;
      CopyMem (Data, Instance->ClientCert, *DataSize);
      break;
    case EfiTlsConfigDataTypeHostPrivateKey:
      if (*DataSize < Instance->ClientPrivateKeySize) {
        *DataSize = Instance->ClientPrivateKeySize;
        Status    = EFI_BUFFER_TOO_SMALL;
        goto ON_EXIT;
      }

      *DataSize = Instance->ClientPrivateKeySize;
      CopyMem (Data, Instance->ClientPrivateKey, *DataSize);
      break;
    default:
      Status = EFI_UNSUPPORTED;
      // goto ON_EXIT;
  }

ON_EXIT:
  gBS->RestoreTPL (OldTpl);
  return Status;
}
