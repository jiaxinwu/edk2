/** @file
  EFI Tls protocol implementation.

**/

#ifndef __EFI_TLS_IMPL_H__
#define __EFI_TLS_IMPL_H__

#include <Uefi.h>

//
// Libraries
//
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseLib.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/NetLib.h>
#include <Library/BaseCryptLib.h>

#include <Library/TimerLib.h> /// Performance Test.

//
// Driver Protocols
//
#include <Protocol/ServiceBinding.h>

//
// Consumed Protocols
//
#include <Protocol/Tls.h>
#include <Protocol/TlsConfig.h>

#include "TlsDriver.h"
#include "TlsPrivate.h"

//
// Driver Version
//
#define TLS_VERSION  0x00000000

//
// Protocol instances
//
extern EFI_SERVICE_BINDING_PROTOCOL  mTlsServiceBinding;

extern EFI_TLS_PROTOCOL                mTlsProtocol;
extern EFI_TLS_CONFIGURATION_PROTOCOL  mTlsConfigurationProtocol;

//
// Tls related
//
#define TLS_STATE_UNCONFIGED  0
#define TLS_STATE_CONFIGED    1
#define TLS_STATE_DESTROY     2

//
// Others Declaration
//
EFI_STATUS
CreateClientHello (
  IN     TLS_INSTANCE  *TlsInstance,
  IN OUT UINT8         *Buffer,
  IN OUT UINTN         *BufferSize
  );

EFI_STATUS
CreateResponsePacket (
  IN     TLS_INSTANCE  *TlsInstance,
  IN     UINT8         *BufferIn,
  IN     UINTN         BufferInSize,
  IN OUT UINT8         *BufferOut,
  IN OUT UINTN         *BufferOutSize
  );

EFI_STATUS
CreateAlertNotify (
  IN     TLS_INSTANCE  *TlsInstance,
  IN OUT UINT8         *Buffer,
  IN OUT UINTN         *BufferSize
  );

EFI_STATUS
EcryptPacket (
  IN     TLS_INSTANCE           *TlsInstance,
  IN OUT EFI_TLS_FRAGMENT_DATA  **FragmentTable,
  IN     UINT32                 *FragmentCount
  );

EFI_STATUS
DecryptPacket (
  IN     TLS_INSTANCE           *TlsInstance,
  IN OUT EFI_TLS_FRAGMENT_DATA  **FragmentTable,
  IN     UINT32                 *FragmentCount
  );

//
// Tls Protocol Declaration
//
EFI_STATUS
EFIAPI
TlsSetSessionData (
  IN     EFI_TLS_PROTOCOL           *This,
  IN     EFI_TLS_SESSION_DATA_TYPE  DataType,
  IN     VOID                       *Data,
  IN     UINTN                      DataSize
  );

EFI_STATUS
EFIAPI
TlsGetSessionData (
  IN     EFI_TLS_PROTOCOL           *This,
  IN     EFI_TLS_SESSION_DATA_TYPE  DataType,
  IN OUT VOID                       *Data,
  IN OUT UINTN                      *DataSize
  );

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
  );

EFI_STATUS
EFIAPI
TlsProcessPacket (
  IN     EFI_TLS_PROTOCOL       *This,
  IN OUT EFI_TLS_FRAGMENT_DATA  **FragmentTable,
  IN     UINT32                 *FragmentCount,
  IN     EFI_TLS_CRYPT_MODE     CryptMode
  );

EFI_STATUS
EFIAPI
TlsConfigurationSetData (
  IN     EFI_TLS_CONFIGURATION_PROTOCOL  *This,
  IN     EFI_TLS_CONFIG_DATA_TYPE        DataType,
  IN     VOID                            *Data,
  IN     UINTN                           DataSize
  );

EFI_STATUS
EFIAPI
TlsConfigurationGetData (
  IN     EFI_TLS_CONFIGURATION_PROTOCOL  *This,
  IN     EFI_TLS_CONFIG_DATA_TYPE        DataType,
  IN OUT VOID                            *Data,
  IN OUT UINTN                           *DataSize
  );

#endif
