/** @file
  EFI Tls protocol implementation.

**/

#ifndef _EFI_TLS_PRIVATE_H_
#define _EFI_TLS_PRIVATE_H_

#include <Base.h>

#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/rc4.h>
#include <openssl/aes.h>

int
RAND_pseudo_bytes (
  unsigned char  *buf,
  int            num
  );

void
RAND_seed (
  const void  *buf,
  int         num
  );

#pragma pack (push, 1)

// TLS Version
#define TLS10_PROTOCOL_VERSION_MAJOR  0x03
#define TLS10_PROTOCOL_VERSION_MINOR  0x01
#define TLS11_PROTOCOL_VERSION_MAJOR  0x03
#define TLS11_PROTOCOL_VERSION_MINOR  0x02
#define TLS12_PROTOCOL_VERSION_MAJOR  0x03
#define TLS12_PROTOCOL_VERSION_MINOR  0x03

//
// Cipher Suite
//
#define TLS_NULL_WITH_NULL_NULL       {0x00, 0x00}            /// None.
#define TLS_RSA_WITH_RC4_128_SHA      {0x00, 0x05}            /// RC4 is stream cipher with a dynamic secret key size(1-255).
#define TLS_RSA_WITH_AES_128_CBC_SHA  {0x00, 0x2F}            /// AES is block cipher with a fixed block size of 128 bits(16 bytes), and a key size of 128, 192, or 256 bits.

//
// Content Type
//
typedef enum {
  TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20,
  TLS_CONTENT_TYPE_ALERT              = 21,
  TLS_CONTENT_TYPE_HANDSHAKE          = 22,
  TLS_CONTENT_TYPE_APPLICATION_DATA   = 23,
} TLS_CONTENT_TYPE;

//
// Type for Change Cipher Spec
//
typedef enum {
  TLS_CHANGE_CIPHER_SPEC_TYPE_CHANGE_CIPHER_SPEC = 1,
} TLS_CHANGE_CIPHER_SPEC_TYPE;

//
// Handshake Type
//
typedef enum {
  TLS_HANDSHAKE_TYPE_HELLO_REQUEST       = 0,
  TLS_HANDSHAKE_TYPE_CLIENT_HELLO        = 1,
  TLS_HANDSHAKE_TYPE_SERVER_HELLO        = 2,
  TLS_HANDSHAKE_TYPE_CERTIFICATE         = 11,
  TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 12,
  TLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST = 13,
  TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE   = 14,
  TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY  = 15,
  TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = 16,
  TLS_HANDSHAKE_TYPE_FINISHED            = 20,
} TLS_HANDSHAKE_TYPE;

//
// Compression Method
//
typedef enum {
  TLS_COPRESSION_METHOD_NULL = 0,
} TLS_COPRESSION_METHOD;

//
// Alert Level
//
typedef enum {
  TLS_ALERT_LEVEL_WARNING = 1,
  TLS_ALERT_LEVEL_FATAL   = 2,
} TLS_ALERT_LEVEL;

//
// Alert Description
//
typedef enum {
  TLS_ALERT_DESCRIPTION_CLOSE_NOTIFY            = 0,
  TLS_ALERT_DESCRIPTION_UNEXPECTED_MESSAGE      = 10,
  TLS_ALERT_DESCRIPTION_BAD_RECORD_MAX          = 20,
  TLS_ALERT_DESCRIPTION_DECRYPTION_FAILED       = 21,
  TLS_ALERT_DESCRIPTION_RECORD_OVERFLOW         = 22,
  TLS_ALERT_DESCRIPTION_DECOMPRESSION_FAILURE   = 30,
  TLS_ALERT_DESCRIPTION_HANDSHAKE_FAILURE       = 40,
  TLS_ALERT_DESCRIPTION_NO_CERTIFICATE          = 41, // SSL3 only
  TLS_ALERT_DESCRIPTION_BAD_CERTIFICATE         = 42,
  TLS_ALERT_DESCRIPTION_UNSUPPORTED_CERTIFICATE = 43,
  TLS_ALERT_DESCRIPTION_CERTIFICATE_REVOKED     = 44,
  TLS_ALERT_DESCRIPTION_CERTIFICATE_EXPIRED     = 45,
  TLS_ALERT_DESCRIPTION_CERTIFICATE_UNKNOWN     = 46,
  TLS_ALERT_DESCRIPTION_ILLEGAL_PARAMETER       = 47,
  TLS_ALERT_DESCRIPTION_UNKNOWN_CA              = 48,
  TLS_ALERT_DESCRIPTION_ACCESS_DENIED           = 49,
  TLS_ALERT_DESCRIPTION_DECODE_ERROR            = 50,
  TLS_ALERT_DESCRIPTION_DECRYPT_ERROR           = 51,
  TLS_ALERT_DESCRIPTION_EXPORT_RESTRICTION      = 60,
  TLS_ALERT_DESCRIPTION_PROTOCOL_VERSION        = 70,
  TLS_ALERT_DESCRIPTION_INSUFFICIENT_SECURITY   = 71,
  TLS_ALERT_DESCRIPTION_INTERNAL_ERROR          = 80,
  TLS_ALERT_DESCRIPTION_USER_CANCELED           = 90,
  TLS_ALERT_DESCRIPTION_NO_RENEGOTIATION        = 100,
  TLS_ALERT_DESCRIPTION_UNSUPPORTED_EXTENSION   = 110,
} TLS_ALERT_DESCRIPTION;

typedef struct {
  UINT8              ContentType;
  EFI_TLS_VERSION    Version;
  UINT16             Length;
} TLSRecordHeader;

typedef struct {
  UINT8    Level;
  UINT8    Description;
} TLS_ALERT; /// ALERT

typedef struct {
  UINT8    Type;
} TLS_CHANGE_CIPHER_SPEC; /// CHANGE_CIPHER_SPEC

typedef struct {
  EFI_TLS_VERSION    Version;
  UINT8              Random[46];
} TLS_PRE_MASTER_SECRET;

#pragma pack (pop)

#define RECORD_HEADER_LEN     5 /// ContentType(1) + Version(2) + Length(2)
#define HANDSHAKE_HEADER_LEN  4 /// HandshakeType(1) + Length(3)

#define MAX_SECRETE_SIZE  1024
#define MAX_BUFFER_SIZE   16384 /// 2^14

#define AES_BLOCK_SIZE_CONVERT(x)  (((x) + AES_BLOCK_SIZE) & ~(AES_BLOCK_SIZE - 1))/// AES need 128 bits(16 bytes) block

typedef struct {
  EFI_TLS_VERSION           Version;
  EFI_TLS_CONNECTION_END    ConnectionEnd;
  EFI_TLS_CIPHER            CipherSuite;
  EFI_TLS_COMPRESSION       Compression;
  EFI_TLS_SESSION_ID        SessionId;

  EFI_TLS_RANDOM            ClientRandom;
  EFI_TLS_RANDOM            ServerRandom;

  BOOLEAN                   NeedClientCertificate;

  /// RSA Server PubKey
  RSA                       *ServerRSAPubKey;

  TLS_PRE_MASTER_SECRET     PreMasterSecret;
  EFI_TLS_MASTER_SECRET     MasterSecret;
  UINT8                     KeyBlock[MAX_SECRETE_SIZE];
  UINTN                     KeyBlockLen;
  UINT8                     *ClientWriteMacSecret;
  UINT8                     *ServerWriteMacSecret;
  UINT8                     *ClientWriteKey;
  UINT8                     *ServerWriteKey;
  UINT8                     *ClientWriteIv;
  UINT8                     *ServerWriteIv;
  /// RC4 key
  RC4_KEY                   ClientRc4Key;
  RC4_KEY                   ServerRc4Key;
  /// AES key
  VOID                      *ClientAesKey;
  VOID                      *ServerAesKey;

  UINT64                    ClientSequence;
  UINT64                    ServerSequence;

  UINT8                     ClientVerifyData[12];
  UINT8                     ServerVerifyData[12];

  BOOLEAN                   ServerHelloDone;
  BOOLEAN                   ClientHandShakeFinished;
  BOOLEAN                   ServerHandShakeFinished;

  /// TLS 1.0 and 1.1 used
  SHA_CTX                   Sha1HashCtx;
  MD5_CTX                   Md5HashCtx;
  UINT8                     Md5HandshakeMessages[MD5_DIGEST_LENGTH];
  UINT8                     Sha1HandshakeMessages[SHA_DIGEST_LENGTH];
  /// TLS 1.2 used
  SHA256_CTX                Sha256HashCtx;
  UINT8                     Sha256HandshakeMessages[SHA256_DIGEST_LENGTH];
  /// TODO, add more verify data hash algorithms in TLS1.2 here...
} TLS_SESSION_CONTEXT;

#endif
