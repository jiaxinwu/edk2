/** @file

**/

#include "TlsImpl.h"

EFI_TLS_PROTOCOL  mTlsProtocol = {
  TlsSetSessionData,
  TlsGetSessionData,
  TlsBuildResponsePacket,
  TlsProcessPacket
};

EFI_STATUS
EFIAPI
TlsSetSessionData (
  IN     EFI_TLS_PROTOCOL           *This,
  IN     EFI_TLS_SESSION_DATA_TYPE  DataType,
  IN     VOID                       *Data,
  IN     UINTN                      DataSize
  )
{
  EFI_STATUS    Status;
  TLS_INSTANCE  *Instance;

  EFI_TPL  OldTpl;

  Status = EFI_SUCCESS;

  if ((This == NULL) || (Data == NULL) || (DataSize == 0)) {
    return EFI_INVALID_PARAMETER;
  }

  OldTpl = gBS->RaiseTPL (TPL_CALLBACK);

  Instance = TLS_INSTANCE_FROM_PROTOCOL_THIS (This);

  if ((DataType != EfiTlsSessionState) && (Instance->TlsSessionState != EfiTlsSessionNotStarted)) {
    Status = EFI_NOT_READY;
    goto ON_EXIT;
  }

  switch (DataType) {
    //
    // Session Configuration
    //
    case EfiTlsVersion:
      ASSERT (DataSize == sizeof (EFI_TLS_VERSION));
      CopyMem (&Instance->TlsSessionContext.Version, Data, DataSize);
      break;
    case EfiTlsConnectionEnd:
      ASSERT (DataSize == sizeof (EFI_TLS_CONNECTION_END));
      Instance->TlsSessionContext.ConnectionEnd = *(EFI_TLS_CONNECTION_END *)Data;
      break;
    case EfiTlsCipher:
      Instance->TlsCipher = AllocatePool (DataSize);
      if (Instance->TlsCipher == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
        goto ON_EXIT;
      }

      Instance->TlsCipherNum = (UINT16)(DataSize/sizeof (EFI_TLS_CIPHER));
      CopyMem (Instance->TlsCipher, Data, DataSize);
      break;
    case EfiTlsCompressionMethod:
      Instance->TlsCompression = AllocatePool (DataSize);
      if (Instance->TlsCompression == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
        goto ON_EXIT;
      }

      Instance->TlsCompressionNum = (UINT16)(DataSize/sizeof (EFI_TLS_COMPRESSION));
      CopyMem (Instance->TlsCompression, Data, DataSize);
      break;
    case EfiTlsExtensionData:
      Instance->TlsExtension = AllocatePool (DataSize);
      if (Instance->TlsExtension == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
        goto ON_EXIT;
      }

      Instance->TlsExtensionLength = DataSize;
      CopyMem (Instance->TlsExtension, Data, DataSize);
      break;
    case EfiTlsVerifyMethod:
      ASSERT (DataSize == sizeof (EFI_TLS_VERIFY));
      CopyMem (&Instance->TlsVerify, Data, DataSize);
      break;
    case EfiTlsSessionID:
      ASSERT (DataSize == sizeof (EFI_TLS_SESSION_ID));
      Instance->TlsResumeSessionID = AllocatePool (DataSize);
      if (Instance->TlsResumeSessionID == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
        goto ON_EXIT;
      }

      CopyMem (Instance->TlsResumeSessionID, Data, DataSize);
      break;
    case EfiTlsSessionState:
      ASSERT (DataSize == sizeof (EFI_TLS_SESSION_STATE));
      Instance->TlsSessionState = *(EFI_TLS_SESSION_STATE *)Data;
      break;
    //
    // Session information
    //
    case EfiTlsClientRandom:
      Status = EFI_ACCESS_DENIED;
      break;
    case EfiTlsServerRandom:
      Status = EFI_ACCESS_DENIED;
      break;
    case EfiTlsKeyMaterial:
      Status = EFI_ACCESS_DENIED;
      break;
    //
    // Unsupported type.
    //
    default:
      Status = EFI_UNSUPPORTED;
  }

ON_EXIT:
  gBS->RestoreTPL (OldTpl);
  return Status;
}

EFI_STATUS
EFIAPI
TlsGetSessionData (
  IN     EFI_TLS_PROTOCOL           *This,
  IN     EFI_TLS_SESSION_DATA_TYPE  DataType,
  IN OUT VOID                       *Data,
  IN OUT UINTN                      *DataSize
  )
{
  EFI_STATUS    Status;
  TLS_INSTANCE  *Instance;

  EFI_TPL  OldTpl;

  Status = EFI_SUCCESS;

  if ((This == NULL) || (Data == NULL) || (DataSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  OldTpl = gBS->RaiseTPL (TPL_CALLBACK);

  Instance = TLS_INSTANCE_FROM_PROTOCOL_THIS (This);

  if ((Instance->TlsSessionState == EfiTlsSessionNotStarted) &&
      ((DataType == EfiTlsSessionID) || (DataType == EfiTlsClientRandom) ||
       (DataType == EfiTlsServerRandom) || (DataType == EfiTlsKeyMaterial)))
  {
    Status = EFI_NOT_READY;
    goto ON_EXIT;
  }

  switch (DataType) {
    case EfiTlsVersion:
      if (*DataSize < sizeof (EFI_TLS_VERSION)) {
        *DataSize = sizeof (EFI_TLS_VERSION);
        Status    = EFI_BUFFER_TOO_SMALL;
        goto ON_EXIT;
      }

      *DataSize = sizeof (EFI_TLS_VERSION);
      CopyMem (Data, &Instance->TlsSessionContext.Version, *DataSize);
      break;
    case EfiTlsConnectionEnd:
      if (*DataSize < sizeof (EFI_TLS_CONNECTION_END)) {
        *DataSize = sizeof (EFI_TLS_CONNECTION_END);
        Status    = EFI_BUFFER_TOO_SMALL;
        goto ON_EXIT;
      }

      *DataSize = sizeof (EFI_TLS_CONNECTION_END);
      CopyMem (Data, &Instance->TlsSessionContext.ConnectionEnd, *DataSize);
      break;
    case EfiTlsCipher: /// Get the current session cipher suite
      if (*DataSize < sizeof (EFI_TLS_CIPHER)) {
        *DataSize = sizeof (EFI_TLS_CIPHER);
        Status    = EFI_BUFFER_TOO_SMALL;
        goto ON_EXIT;
      }

      *DataSize = sizeof (EFI_TLS_CIPHER);
      CopyMem (Data, &Instance->TlsSessionContext.CipherSuite, *DataSize);
      break;
    case EfiTlsCompressionMethod: /// Get the current session compression method
      if (*DataSize < sizeof (EFI_TLS_COMPRESSION)) {
        *DataSize = sizeof (EFI_TLS_COMPRESSION);
        Status    = EFI_BUFFER_TOO_SMALL;
        goto ON_EXIT;
      }

      *DataSize = sizeof (EFI_TLS_COMPRESSION);
      CopyMem (Data, &Instance->TlsSessionContext.Compression, *DataSize);
      break;
    case EfiTlsExtensionData:
      if (*DataSize < Instance->TlsExtensionLength) {
        *DataSize = Instance->TlsExtensionLength;
        Status    = EFI_BUFFER_TOO_SMALL;
        goto ON_EXIT;
      } else if (Instance->TlsExtension == NULL) {
        Status = EFI_NOT_FOUND;
        goto ON_EXIT;
      }

      *DataSize = Instance->TlsExtensionLength;
      CopyMem (Data, Instance->TlsExtension, *DataSize);
      break;
    case EfiTlsVerifyMethod:
      if (*DataSize < sizeof (EFI_TLS_VERIFY)) {
        *DataSize = sizeof (EFI_TLS_VERIFY);
        Status    = EFI_BUFFER_TOO_SMALL;
        goto ON_EXIT;
      }

      *DataSize = sizeof (EFI_TLS_VERIFY);
      CopyMem (Data, &Instance->TlsVerify, *DataSize);
      break;
    case EfiTlsSessionID: /// Get the current session ID
      if (*DataSize < sizeof (EFI_TLS_SESSION_ID)) {
        *DataSize = sizeof (EFI_TLS_SESSION_ID);
        Status    = EFI_BUFFER_TOO_SMALL;
        goto ON_EXIT;
      }

      *DataSize = sizeof (EFI_TLS_SESSION_ID);
      CopyMem (Data, &Instance->TlsSessionContext.SessionId, *DataSize);
      break;
    case EfiTlsSessionState:
      if (*DataSize < sizeof (EFI_TLS_SESSION_STATE)) {
        *DataSize = sizeof (EFI_TLS_SESSION_STATE);
        Status    = EFI_BUFFER_TOO_SMALL;
        goto ON_EXIT;
      }

      *DataSize = sizeof (EFI_TLS_SESSION_STATE);
      CopyMem (Data, &Instance->TlsSessionState, *DataSize);
      break;
    case EfiTlsClientRandom:
      if (*DataSize < sizeof (EFI_TLS_RANDOM)) {
        *DataSize = sizeof (EFI_TLS_RANDOM);
        Status    = EFI_BUFFER_TOO_SMALL;
        goto ON_EXIT;
      }

      *DataSize = sizeof (EFI_TLS_RANDOM);
      CopyMem (Data, &Instance->TlsSessionContext.ClientRandom, *DataSize);
      break;
    case EfiTlsServerRandom:
      if (*DataSize < sizeof (EFI_TLS_RANDOM)) {
        *DataSize = sizeof (EFI_TLS_RANDOM);
        Status    = EFI_BUFFER_TOO_SMALL;
        goto ON_EXIT;
      }

      *DataSize = sizeof (EFI_TLS_RANDOM);
      CopyMem (Data, &Instance->TlsSessionContext.ServerRandom, *DataSize);
      break;
    case EfiTlsKeyMaterial:
      if (*DataSize < sizeof (EFI_TLS_MASTER_SECRET)) {
        *DataSize = sizeof (EFI_TLS_MASTER_SECRET);
        Status    = EFI_BUFFER_TOO_SMALL;
        goto ON_EXIT;
      }

      *DataSize = sizeof (EFI_TLS_MASTER_SECRET);
      CopyMem (Data, &Instance->TlsSessionContext.MasterSecret, *DataSize);
      break;
    //
    // Unsupported type.
    //
    default:
      Status = EFI_UNSUPPORTED;
  }

ON_EXIT:
  gBS->RestoreTPL (OldTpl);
  return Status;
}

/**
  Build response packet according to TLS state machine.
  This function is only valid for alert, handshake and change_cipher_spec content type.
**/
EFI_STATUS
EFIAPI
TlsBuildResponsePacket (
  IN     EFI_TLS_PROTOCOL  *This,
  IN     UINT8             *RequestBuffer,
  OPTIONAL
  IN     UINTN             RequestSize,
  OPTIONAL
  OUT UINT8                *Buffer,
  IN OUT UINTN             *BufferSize
  )
{
  EFI_STATUS    Status;
  TLS_INSTANCE  *Instance;

  EFI_TPL  OldTpl;

  Status = EFI_SUCCESS;

  if ((This == NULL) || (Buffer == NULL) || (BufferSize == NULL) || \
      ((RequestBuffer == NULL) && (RequestSize != 0)) || \
      ((RequestBuffer != NULL) && (RequestSize == 0)))
  {
    return EFI_INVALID_PARAMETER;
  }

  OldTpl = gBS->RaiseTPL (TPL_CALLBACK);

  Instance = TLS_INSTANCE_FROM_PROTOCOL_THIS (This);

  if (Instance->TlsSessionContext.ConnectionEnd == EfiTlsServer) {
    gBS->RestoreTPL (OldTpl);
    return EFI_UNSUPPORTED; /// Not support EfiTlsServer currently.
  }

  if ((RequestBuffer == NULL) && (RequestSize == 0)) {
    switch (Instance->TlsSessionState) {
      case EfiTlsSessionNotStarted:
        //
        // ClientHello.
        //
        ASSERT (Instance->TlsSessionContext.ConnectionEnd == EfiTlsClient);
        Status = CreateClientHello (Instance, Buffer, BufferSize);
        if (!EFI_ERROR (Status)) {
          Instance->TlsSessionState = EfiTlsSessionHandShaking;
        }

        break;
      case EfiTlsSessionClosing:
        //
        // Set TLS_ALERT in instance, then create CloseNotify.
        //
        if (Instance->TlsAlert != NULL) {
          FreePool (Instance->TlsAlert);
        }

        Instance->TlsAlert              = AllocateZeroPool (sizeof (TLS_ALERT));
        Instance->TlsAlert->Level       = TLS_ALERT_LEVEL_WARNING;
        Instance->TlsAlert->Description = TLS_ALERT_DESCRIPTION_CLOSE_NOTIFY;

        Status = CreateAlertNotify (Instance, Buffer, BufferSize);

        break;
      case EfiTlsSessionError:
        //
        // Alert message based on error type(Instance->TlsAlert)
        //
        if (Instance->TlsAlert == NULL) {
          Instance->TlsAlert              = AllocateZeroPool (sizeof (TLS_ALERT));
          Instance->TlsAlert->Level       = TLS_ALERT_LEVEL_FATAL;
          Instance->TlsAlert->Description = TLS_ALERT_DESCRIPTION_CLOSE_NOTIFY;
        }

        Status = CreateAlertNotify (Instance, Buffer, BufferSize);

        break;
      default:
        //
        // Current TLS session state is NOT ready to build ResponsePacket.
        //
        Status = EFI_NOT_READY;
    }
  } else {
    //
    // Build response packet according to RequestBuffer.
    //
    Status = CreateResponsePacket (Instance, RequestBuffer, RequestSize, Buffer, BufferSize);
  }

  gBS->RestoreTPL (OldTpl);
  return Status;
}

EFI_STATUS
EFIAPI
TlsProcessPacket (
  IN     EFI_TLS_PROTOCOL       *This,
  IN OUT EFI_TLS_FRAGMENT_DATA  **FragmentTable,
  IN     UINT32                 *FragmentCount,
  IN     EFI_TLS_CRYPT_MODE     CryptMode
  )
{
  EFI_STATUS    Status;
  TLS_INSTANCE  *Instance;

  EFI_TPL  OldTpl;

  Status = EFI_SUCCESS;

  if ((This == NULL) || (FragmentTable == NULL) || (FragmentCount == NULL) || (*FragmentCount == 0)) {
    return EFI_INVALID_PARAMETER;
  }

  OldTpl = gBS->RaiseTPL (TPL_CALLBACK);

  Instance = TLS_INSTANCE_FROM_PROTOCOL_THIS (This);

  if (Instance->TlsSessionContext.ConnectionEnd == EfiTlsServer) {
    Status = EFI_UNSUPPORTED; /// Not support EfiTlsServer currently.
    goto ON_EXIT;
  }

  if (Instance->TlsSessionState != EfiTlsSessionDataTransferring) {
    Status = EFI_NOT_READY;
    goto ON_EXIT;
  }

  //
  // Packet sent or received may have multiply TLS record message(Application data type).
  // So,on input these fragments contain the TLS header and TLS APP payload;
  // on output these fragments also contain the TLS header and TLS APP payload.
  //
  switch (CryptMode) {
    case EfiTlsEncrypt:
      Status = EcryptPacket (Instance, FragmentTable, FragmentCount);
      if (EFI_ERROR (Status)) {
        Instance->TlsSessionState = EfiTlsSessionError;
      }

      break;
    case EfiTlsDecrypt:
      Status = DecryptPacket (Instance, FragmentTable, FragmentCount);
      if (EFI_ERROR (Status)) {
        Instance->TlsSessionState = EfiTlsSessionError;
      }

      break;
    default:
      return EFI_INVALID_PARAMETER;
  }

ON_EXIT:
  gBS->RestoreTPL (OldTpl);
  return Status;
}
