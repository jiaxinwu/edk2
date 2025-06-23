/** @file
  The implementation of the Tls protocol.

**/

#include "TlsImpl.h"

EFI_TLS_CIPHER  RsaRc4_128Sha = TLS_RSA_WITH_RC4_128_SHA;
EFI_TLS_CIPHER  RsaAes_128Sha = TLS_RSA_WITH_AES_128_CBC_SHA;

/// Convert little-endian to big-endian
UINT8 *
TlsEncodeUint8 (
  UINT8  *p,
  UINTN  value,
  UINTN  length
  )
{
  UINT8  *ret;

  ret = p + length;
  ASSERT (length > 0 && length <= sizeof (UINTN));
  while (length--) {
    p[length] = (UINT8)value;
    value   >>= 8;
  }

  return ret;
}

/// Convert big-endian to little-endian
UINTN
TlsDecodeUint8 (
  UINT8  *p,
  UINTN  length
  )
{
  UINTN  val;

  val = 0;
  while (length--) {
    val = (val << 8) | *p++;
  }

  return val;
}

VOID
TlsXOR (
  IN  UINT8  *Data1,
  IN  UINT8  *Data2,
  IN  UINTN  DataLen,
  OUT UINT8  *DataOut
  )
{
  UINTN  Index;

  for (Index = 0; Index < DataLen; Index++) {
    DataOut[Index] = Data1[Index] ^ Data2[Index];
  }
}

VOID
TlsPHash (
  IN CONST EVP_MD  *EvpMd,
  IN       UINT8   *Secret,
  IN       UINTN   SecretLen,
  IN       UINT8   *LabelSeed,
  IN       UINTN   LabelSeedLen,
  IN       UINTN   HashLen,
  OUT      UINT8   *Hash
  )
{
  INTN      LeftLen;
  UINTN     CopyLen;
  UINT8     HashData[MAX (MAX (SHA_DIGEST_LENGTH, MD5_DIGEST_LENGTH), SHA256_DIGEST_LENGTH)];
  UINT32    HashDataLen;
  UINT8     SeedAData[MAX (MAX (SHA_DIGEST_LENGTH, MD5_DIGEST_LENGTH), SHA256_DIGEST_LENGTH)];
  UINT8     *SeedA;
  UINT32    SeedALen;
  HMAC_CTX  HMacCtx;
  UINT8     *HashOutPtr;

  HashOutPtr = Hash;
  LeftLen    = (INTN)HashLen;
  SeedA      = LabelSeed;
  SeedALen   = (UINT32)LabelSeedLen;
  while (LeftLen > 0) {
    HMAC_Init (&HMacCtx, Secret, (UINT32)SecretLen, EvpMd);
    HMAC_Update (&HMacCtx, SeedA, SeedALen);
    HMAC_Final (&HMacCtx, &SeedAData[0], &SeedALen);

    SeedA = &SeedAData[0];
    HMAC_Init (&HMacCtx, Secret, (UINT32)SecretLen, EvpMd);
    HMAC_Update (&HMacCtx, SeedA, SeedALen);
    HMAC_Update (&HMacCtx, LabelSeed, LabelSeedLen);
    HMAC_Final (&HMacCtx, &HashData[0], &HashDataLen);

    CopyLen = MIN ((UINTN)LeftLen, HashDataLen);
    CopyMem (HashOutPtr, HashData, CopyLen);
    HashOutPtr += CopyLen;
    LeftLen    -= CopyLen;
  }

  HMAC_cleanup (&HMacCtx);
}

// Default PRF alg in TLS1.2
VOID
TlsSha256Prf (
  IN  UINT8  *Secret,
  IN  UINTN  SecretLen,
  IN  CHAR8  *Lable,
  IN  UINT8  *Seed1,
  IN  UINTN  Seed1Len,
  IN  UINT8  *Seed2,
  IN  UINTN  Seed2Len,
  IN  UINTN  OutLen,
  OUT UINT8  *Out
  )
{
  UINT8         LableSeed[32 + sizeof (EFI_TLS_RANDOM) * 2];
  UINTN         LableSeedLen;
  UINT8         OutSha256[MAX_SECRETE_SIZE];
  UINTN         OutSha256Len;
  CONST EVP_MD  *EvpMd;
  UINTN         Index;

  LableSeedLen = 0;
  CopyMem (&LableSeed[LableSeedLen], Lable, AsciiStrLen (Lable));
  LableSeedLen += AsciiStrLen (Lable);
  CopyMem (&LableSeed[LableSeedLen], Seed1, Seed1Len);
  LableSeedLen += Seed1Len;
  CopyMem (&LableSeed[LableSeedLen], Seed2, Seed2Len);
  LableSeedLen += Seed2Len;

  OutSha256Len = MAX (OutLen, SHA256_DIGEST_LENGTH);
  EvpMd        = EVP_get_digestbyname ("SHA256");
  TlsPHash (EvpMd, Secret, SecretLen, LableSeed, LableSeedLen, OutSha256Len, OutSha256);

  for (Index = 0; Index < OutLen; Index++) {
    Out[Index] = OutSha256[Index];
  }
}

VOID
TlsMd5Sha1Prf (
  IN  UINT8  *Secret,
  IN  UINTN  SecretLen,
  IN  CHAR8  *Lable,
  IN  UINT8  *Seed1,
  IN  UINTN  Seed1Len,
  IN  UINT8  *Seed2,
  IN  UINTN  Seed2Len,
  IN  UINTN  OutLen,
  OUT UINT8  *Out
  )
{
  UINT8         LableSeed[32 + sizeof (EFI_TLS_RANDOM) * 2];
  UINTN         LableSeedLen;
  UINTN         HalfOfSecretLen;
  UINT8         Secret1[MAX_SECRETE_SIZE/2];
  UINT8         Secret2[MAX_SECRETE_SIZE/2];
  UINT8         OutMd5[MAX_SECRETE_SIZE];
  UINTN         OutMd5Len;
  UINT8         OutSha1[MAX_SECRETE_SIZE];
  UINTN         OutSha1Len;
  CONST EVP_MD  *EvpMd;

  LableSeedLen = 0;
  CopyMem (&LableSeed[LableSeedLen], Lable, AsciiStrLen (Lable));
  LableSeedLen += AsciiStrLen (Lable);
  CopyMem (&LableSeed[LableSeedLen], Seed1, Seed1Len);
  LableSeedLen += Seed1Len;
  CopyMem (&LableSeed[LableSeedLen], Seed2, Seed2Len);
  LableSeedLen += Seed2Len;

  HalfOfSecretLen = SecretLen / 2 + SecretLen % 2;
  CopyMem (&Secret1[0], &Secret[0], HalfOfSecretLen);
  CopyMem (&Secret2[0], &Secret[SecretLen - HalfOfSecretLen], HalfOfSecretLen);

  OutMd5Len = MAX (OutLen, MD5_DIGEST_LENGTH);
  EvpMd     = EVP_get_digestbyname ("MD5");
  TlsPHash (EvpMd, Secret1, HalfOfSecretLen, LableSeed, LableSeedLen, OutMd5Len, &OutMd5[0]);
  OutSha1Len = MAX (OutLen, SHA_DIGEST_LENGTH);
  EvpMd      = EVP_get_digestbyname ("SHA1");
  TlsPHash (EvpMd, Secret2, HalfOfSecretLen, LableSeed, LableSeedLen, OutSha1Len, &OutSha1[0]);

  TlsXOR (&OutMd5[0], &OutSha1[0], OutLen, Out);
}

VOID
TlsCleanSessionContext (
  IN TLS_SESSION_CONTEXT  *TlsSessionContext
  )
{
  //
  // Upon receipt of an fatal alert message, both parties immediately close the connection.
  // Servers and clients are required to forget any session-identifiers, keys, and secrets associated with a failed connection.
  // If an alert with a level of warning is received, the receiving party may decide at its discretion whether to treat this as a fatal error or not.
  //
  if (TlsSessionContext->ServerRSAPubKey != NULL) {
    FreePool (TlsSessionContext->ServerRSAPubKey);
  }

  if (TlsSessionContext->ClientAesKey != NULL) {
    FreePool (TlsSessionContext->ClientAesKey);
  }

  if (TlsSessionContext->ServerAesKey != NULL) {
    FreePool (TlsSessionContext->ServerAesKey);
  }

  ZeroMem (TlsSessionContext, sizeof (TLS_SESSION_CONTEXT));
}

BOOLEAN
TlsIsValidCipherSuite (
  IN  EFI_TLS_CIPHER  *CipherSuite,
  IN  UINT16          SupportedCipherSuiteNum,
  IN  EFI_TLS_CIPHER  *SupportedCipherSuite
  )
{
  UINT16  Index;

  for (Index = 0; Index < SupportedCipherSuiteNum; Index++) {
    if (!CompareMem (&SupportedCipherSuite[Index], CipherSuite, sizeof (EFI_TLS_CIPHER))) {
      return TRUE;
    }
  }

  return FALSE;
}

VOID
TlsInitHandshakeMessage (
  IN OUT TLS_SESSION_CONTEXT  *TlsSessionContext
  )
{
  SHA1_Init (&TlsSessionContext->Sha1HashCtx);
  MD5_Init (&TlsSessionContext->Md5HashCtx);
  SHA256_Init (&TlsSessionContext->Sha256HashCtx);
}

VOID
TlsUpdateHandshakeMessage (
  IN OUT TLS_SESSION_CONTEXT  *TlsSessionContext,
  IN     UINT8                *Data,
  IN     UINTN                DataLen
  )
{
  SHA1_Update (&TlsSessionContext->Sha1HashCtx, Data, DataLen);
  MD5_Update (&TlsSessionContext->Md5HashCtx, Data, DataLen);
  SHA256_Update (&TlsSessionContext->Sha256HashCtx, Data, DataLen);
}

VOID
TlsFinishHandshakeMessage (
  IN OUT TLS_SESSION_CONTEXT  *TlsSessionContext
  )
{
  SHA_CTX     Sha1HashCtx;
  MD5_CTX     Md5HashCtx;
  SHA256_CTX  Sha256HashCtx;

  CopyMem (&Sha1HashCtx, &TlsSessionContext->Sha1HashCtx, sizeof (Sha1HashCtx));
  CopyMem (&Md5HashCtx, &TlsSessionContext->Md5HashCtx, sizeof (Md5HashCtx));
  CopyMem (&Sha256HashCtx, &TlsSessionContext->Sha256HashCtx, sizeof (Sha256HashCtx));

  SHA1_Final ((UINT8 *)&TlsSessionContext->Sha1HandshakeMessages[0], &Sha1HashCtx);
  MD5_Final ((UINT8 *)&TlsSessionContext->Md5HandshakeMessages[0], &Md5HashCtx);
  SHA256_Final ((UINT8 *)&TlsSessionContext->Sha256HandshakeMessages[0], &Sha256HashCtx);
}

EFI_STATUS
TlsGetServerCertificate (
  IN     UINT8   *Cert,
  IN     UINT32  CertLen,
  IN OUT UINT8   **RequiredCert1,
  IN OUT UINT32  *RequiredCert1Len,
  IN OUT UINT8   **RequiredCert2,
  IN OUT UINT32  *RequiredCert2Len
  )
{
  UINT8   *CertItem;
  UINT32  CertItemLen;

  UINT8   *LastCert;
  UINT32  LastCertLen;

  LastCert    = NULL;
  LastCertLen = 0;

  CertItem    = Cert;
  CertItemLen = (UINT32)TlsDecodeUint8 (Cert, 3); /// Item length - 3 bytes

  //
  // First cert
  //
  *RequiredCert1Len = CertItemLen;
  *RequiredCert1    = CertItem + 3;

  //
  // Last Cert
  //
  while ((UINTN)CertItem < (UINTN)Cert + CertLen) {
    LastCert    = CertItem;
    LastCertLen = (UINT32)TlsDecodeUint8 (CertItem, 3); /// Item length - 3 bytes;
    CertItem    = CertItem + 3 + LastCertLen;
  }

  if ((UINTN)LastCert != (UINTN)Cert) {
    *RequiredCert2Len = LastCertLen;
    *RequiredCert2    = LastCert + 3;
  }

  return EFI_SUCCESS;
}

EVP_PKEY *
TlsGetPubkeyFromCertificate (
  IN UINT8   *Cert,
  IN UINT32  CertLen
  )
{
  X509      *X509Cert;
  EVP_PKEY  *EvpPubKey;

  X509Cert = d2i_X509 (NULL, &Cert, CertLen);
  if (X509Cert == NULL) {
    DEBUG ((EFI_D_ERROR, "Bad certificate"));
    return NULL;
  }

  EvpPubKey = X509_get_pubkey (X509Cert);

  return EvpPubKey;
}

VOID
TlsGetServerVerifyData (
  IN OUT TLS_SESSION_CONTEXT  *TlsSessionContext
  )
{
  if (TlsSessionContext->Version.Minor == TLS12_PROTOCOL_VERSION_MINOR) {
    // PRF(master_secret, "server finished", SHA-256(handshake_messages)) [0..11];
    TlsSha256Prf (
                  (UINT8 *)&TlsSessionContext->MasterSecret,
                  sizeof (TlsSessionContext->MasterSecret),
                  "server finished",
                  NULL,
                  0,
                  (UINT8 *)&TlsSessionContext->Sha256HandshakeMessages,
                  sizeof (TlsSessionContext->Sha256HandshakeMessages),
                  sizeof (TlsSessionContext->ServerVerifyData),
                  TlsSessionContext->ServerVerifyData
                  );
  } else {
    // PRF(master_secret, "server finished", MD5(handshake_messages) + SHA-1(handshake_messages)) [0..11];
    TlsMd5Sha1Prf (
                   (UINT8 *)&TlsSessionContext->MasterSecret,
                   sizeof (TlsSessionContext->MasterSecret),
                   "server finished",
                   (UINT8 *)&TlsSessionContext->Md5HandshakeMessages,
                   sizeof (TlsSessionContext->Md5HandshakeMessages),
                   (UINT8 *)&TlsSessionContext->Sha1HandshakeMessages,
                   sizeof (TlsSessionContext->Sha1HandshakeMessages),
                   sizeof (TlsSessionContext->ServerVerifyData),
                   TlsSessionContext->ServerVerifyData
                   );
  }
}

VOID
TlsGetClientVerifyData (
  IN OUT TLS_SESSION_CONTEXT  *TlsSessionContext
  )
{
  if (TlsSessionContext->Version.Minor == TLS12_PROTOCOL_VERSION_MINOR) {
    // PRF(master_secret, "server finished", SHA-256(handshake_messages)) [0..11];
    TlsSha256Prf (
                  (UINT8 *)&TlsSessionContext->MasterSecret,
                  sizeof (TlsSessionContext->MasterSecret),
                  "client finished",
                  NULL,
                  0,
                  (UINT8 *)&TlsSessionContext->Sha256HandshakeMessages,
                  sizeof (TlsSessionContext->Sha256HandshakeMessages),
                  sizeof (TlsSessionContext->ClientVerifyData),
                  TlsSessionContext->ClientVerifyData
                  );
  } else {
    // PRF(master_secret, "client finished", MD5(handshake_messages) + SHA-1(handshake_messages)) [0..11];
    TlsMd5Sha1Prf (
                   (UINT8 *)&TlsSessionContext->MasterSecret,
                   sizeof (TlsSessionContext->MasterSecret),
                   "client finished",
                   (UINT8 *)&TlsSessionContext->Md5HandshakeMessages,
                   sizeof (TlsSessionContext->Md5HandshakeMessages),
                   (UINT8 *)&TlsSessionContext->Sha1HandshakeMessages,
                   sizeof (TlsSessionContext->Sha1HandshakeMessages),
                   sizeof (TlsSessionContext->ClientVerifyData),
                   TlsSessionContext->ClientVerifyData
                   );
  }
}

VOID
TlsGenKeyByPreMasterSecret (
  IN OUT TLS_SESSION_CONTEXT  *TlsSessionContext
  )
{
  char  RndSeed[] = "string to make the random number generator think it has entropy";

  UINTN  DigestSize;
  UINTN  KeySize;
  UINTN  IvSize;

  OpenSSL_add_all_digests ();
  RAND_seed (RndSeed, sizeof (RndSeed)); /* or RSA_public_encrypt may fail */

  if (CompareMem (&TlsSessionContext->CipherSuite, &RsaRc4_128Sha, sizeof (EFI_TLS_CIPHER)) == 0) {
    //
    // TLS_RSA_WITH_RC4_128_SHA
    //
    DigestSize = SHA_DIGEST_LENGTH;
    KeySize    = 128 / 8;
    IvSize     = 0;
  } else if (CompareMem (&TlsSessionContext->CipherSuite, &RsaAes_128Sha, sizeof (EFI_TLS_CIPHER)) == 0) {
    //
    // TLS_RSA_WITH_AES_128_CBC_SHA
    //
    DigestSize = SHA_DIGEST_LENGTH;
    KeySize    = 128 / 8;
    IvSize     = 16;
  } else {
    DigestSize = 0;
    KeySize    = 0;
    IvSize     = 0;
    ASSERT (FALSE);
  }

  TlsSessionContext->KeyBlockLen = (DigestSize + KeySize + IvSize) * 2;

  //
  // MasterSecret = PRF (PreMasterSecret, "master secret", ClientRandom + ServerRandom)
  //
  if (TlsSessionContext->Version.Minor == TLS12_PROTOCOL_VERSION_MINOR) {
    TlsSha256Prf (
                  (UINT8 *)&TlsSessionContext->PreMasterSecret,
                  sizeof (TlsSessionContext->PreMasterSecret),
                  "master secret",
                  (UINT8 *)&TlsSessionContext->ClientRandom,
                  sizeof (TlsSessionContext->ClientRandom),
                  (UINT8 *)&TlsSessionContext->ServerRandom,
                  sizeof (TlsSessionContext->ServerRandom),
                  sizeof (TlsSessionContext->MasterSecret),
                  (UINT8 *)&TlsSessionContext->MasterSecret
                  );
    //
    // KeyBlock = PRF (MasterSecret, "key expansion", ServerRandom + ClientRandom)
    //
    TlsSha256Prf (
                  (UINT8 *)&TlsSessionContext->MasterSecret,
                  sizeof (TlsSessionContext->MasterSecret),
                  "key expansion",
                  (UINT8 *)&TlsSessionContext->ServerRandom,
                  sizeof (TlsSessionContext->ServerRandom),
                  (UINT8 *)&TlsSessionContext->ClientRandom,
                  sizeof (TlsSessionContext->ClientRandom),
                  TlsSessionContext->KeyBlockLen,
                  &TlsSessionContext->KeyBlock[0]
                  );
  } else {
    TlsMd5Sha1Prf (
                   (UINT8 *)&TlsSessionContext->PreMasterSecret,
                   sizeof (TlsSessionContext->PreMasterSecret),
                   "master secret",
                   (UINT8 *)&TlsSessionContext->ClientRandom,
                   sizeof (TlsSessionContext->ClientRandom),
                   (UINT8 *)&TlsSessionContext->ServerRandom,
                   sizeof (TlsSessionContext->ServerRandom),
                   sizeof (TlsSessionContext->MasterSecret),
                   (UINT8 *)&TlsSessionContext->MasterSecret
                   );
    //
    // KeyBlock = PRF (MasterSecret, "key expansion", ServerRandom + ClientRandom)
    //
    TlsMd5Sha1Prf (
                   (UINT8 *)&TlsSessionContext->MasterSecret,
                   sizeof (TlsSessionContext->MasterSecret),
                   "key expansion",
                   (UINT8 *)&TlsSessionContext->ServerRandom,
                   sizeof (TlsSessionContext->ServerRandom),
                   (UINT8 *)&TlsSessionContext->ClientRandom,
                   sizeof (TlsSessionContext->ClientRandom),
                   TlsSessionContext->KeyBlockLen,
                   &TlsSessionContext->KeyBlock[0]
                   );
  }

  //
  // client_write_MAC_secret = key_block[hash_size]
  // server_write_MAC_secret = key_block[hash_size]
  // client_write_key        = key_block[key_material_length]
  // server_write_key        = key_block[key_material_length]
  //
  TlsSessionContext->ClientWriteMacSecret = &TlsSessionContext->KeyBlock[0];
  TlsSessionContext->ServerWriteMacSecret = &TlsSessionContext->KeyBlock[DigestSize];
  TlsSessionContext->ClientWriteKey       = &TlsSessionContext->KeyBlock[DigestSize * 2];
  TlsSessionContext->ServerWriteKey       = &TlsSessionContext->KeyBlock[DigestSize * 2 + KeySize];
  TlsSessionContext->ClientWriteIv        = &TlsSessionContext->KeyBlock[DigestSize * 2 + KeySize * 2];
  TlsSessionContext->ServerWriteIv        = &TlsSessionContext->KeyBlock[DigestSize * 2 + KeySize * 2 + IvSize];
}

EFI_STATUS
TlsCommonEncryption (
  IN  TLS_INSTANCE  *TlsInstance,
  IN  UINT8         ContentType,
  IN  UINT8         *Buffer,
  IN  UINT16        BufferSize,
  OUT UINT8         *EcryptedBuffer,
  OUT UINT16        *EcryptedBufferSize
  )
{
  TLSRecordHeader  TempRecordHeader;
  UINT8            *HmacBuffer;

  EFI_STATUS    Status;
  CONST EVP_MD  *EvpMd;
  HMAC_CTX      HMacCtx;
  UINT32        HMacDataLen;
  UINT64        Sequence;

  //
  // Only for block cipher(AES)
  //
  UINT8   *MessageBlock;
  UINT16  MessageBlockSize;
  UINT8   Pad;
  UINT16  PadSize;
  //
  // TLS 1.1 and 1.2 required
  //
  UINTN  IvLen;
  UINT8  *ClientExplicitIv;
  UINT8  *ClientMask;

  MessageBlock     = NULL;
  ClientExplicitIv = NULL;
  ClientMask       = NULL;

  Status = EFI_SUCCESS;

  if ((CompareMem (&TlsInstance->TlsSessionContext.CipherSuite, &RsaAes_128Sha, sizeof (EFI_TLS_CIPHER)) == 0) &&
      ((TlsInstance->TlsSessionContext.Version.Minor == TLS11_PROTOCOL_VERSION_MINOR) ||
       (TlsInstance->TlsSessionContext.Version.Minor == TLS12_PROTOCOL_VERSION_MINOR)))
  {
    IvLen            = 128/8;
    MessageBlockSize = AES_BLOCK_SIZE_CONVERT (IvLen + BufferSize + SHA_DIGEST_LENGTH);
  } else {
    IvLen            = 0;
    MessageBlockSize = AES_BLOCK_SIZE_CONVERT (BufferSize + SHA_DIGEST_LENGTH);
  }

  HmacBuffer = AllocatePool (BufferSize + SHA_DIGEST_LENGTH);
  ASSERT (HmacBuffer != NULL);

  //
  // Calculate HMAC
  //
  TempRecordHeader.ContentType   = ContentType;
  TempRecordHeader.Version.Major = TlsInstance->TlsSessionContext.Version.Major;
  TempRecordHeader.Version.Minor = TlsInstance->TlsSessionContext.Version.Minor;
  TempRecordHeader.Length        = HTONS (BufferSize);

  CopyMem (HmacBuffer, Buffer, BufferSize);

  //
  // Gen HMAC
  // HMAC_hash(MAC_write_secret, seq_num + Record.type +
  //           Record.version + Record.length +
  //           Record.fragment));
  //
  EvpMd = EVP_get_digestbyname ("SHA1");
  HMAC_Init (&HMacCtx, TlsInstance->TlsSessionContext.ClientWriteMacSecret, SHA_DIGEST_LENGTH, EvpMd); /// MAC_write_secret
  Sequence = NTOHLL (TlsInstance->TlsSessionContext.ClientSequence);
  HMAC_Update (&HMacCtx, (UINT8 *)&Sequence, sizeof (Sequence));         /// seq_num
  HMAC_Update (&HMacCtx, (UINT8 *)&TempRecordHeader, RECORD_HEADER_LEN); /// Record Header
  HMAC_Update (&HMacCtx, (UINT8 *)Buffer, BufferSize);                   /// Record Data
  HMAC_Final (&HMacCtx, (UINT8 *)HmacBuffer + BufferSize, &HMacDataLen);

  TlsInstance->TlsSessionContext.ClientSequence++;

  //
  // Encrypte: RC4 (Buffer + HMAC, Rc4Key) or  AES ([Iv] + Buffer + HMAC + Pad + PadSize, AesKey)
  //
  if (CompareMem (&TlsInstance->TlsSessionContext.CipherSuite, &RsaRc4_128Sha, sizeof (EFI_TLS_CIPHER)) == 0) {
    //
    // RC4 encryption
    //
    RC4 (
         &TlsInstance->TlsSessionContext.ClientRc4Key, /// Must be initialized before encryption
         (UINT32)(BufferSize + SHA_DIGEST_LENGTH),
         HmacBuffer,
         EcryptedBuffer
         );
    *EcryptedBufferSize = BufferSize + SHA_DIGEST_LENGTH;
  } else if (CompareMem (&TlsInstance->TlsSessionContext.CipherSuite, &RsaAes_128Sha, sizeof (EFI_TLS_CIPHER)) == 0) {
    MessageBlock = AllocatePool (MessageBlockSize);
    ASSERT (MessageBlock != NULL);

    if ((TlsInstance->TlsSessionContext.Version.Minor == TLS11_PROTOCOL_VERSION_MINOR) ||
        (TlsInstance->TlsSessionContext.Version.Minor == TLS12_PROTOCOL_VERSION_MINOR))
    {
      //
      // Pad first
      //
      if (MessageBlockSize > IvLen + BufferSize + SHA_DIGEST_LENGTH) {
        PadSize = MessageBlockSize - BufferSize - SHA_DIGEST_LENGTH - (UINT16)IvLen;
        Pad     = (UINT8)(PadSize - 1);
        SetMem (MessageBlock, MessageBlockSize, Pad);
      }

      //
      // Generate IV
      //
      ClientExplicitIv = AllocatePool (IvLen);
      ASSERT (ClientExplicitIv != NULL);
      ClientMask = AllocateZeroPool (IvLen);
      ASSERT (ClientMask != NULL);
      RAND_pseudo_bytes (ClientExplicitIv, (UINT32)IvLen);
      CopyMem (MessageBlock, ClientExplicitIv, IvLen);

      CopyMem (MessageBlock + IvLen, HmacBuffer, BufferSize + SHA_DIGEST_LENGTH);

      //
      // AES encryption
      //
      AES_cbc_encrypt (
                       MessageBlock,
                       EcryptedBuffer,
                       (UINT32)MessageBlockSize,
                       (AES_KEY *)TlsInstance->TlsSessionContext.ClientAesKey, /// Must be initialized before encryption
                       ClientMask,
                       AES_ENCRYPT
                       );

      FreePool (ClientExplicitIv);
      FreePool (ClientMask);
    } else {
      //
      // Pad first
      //
      if (MessageBlockSize > BufferSize + SHA_DIGEST_LENGTH) {
        PadSize = MessageBlockSize - BufferSize - SHA_DIGEST_LENGTH;
        Pad     = (UINT8)(PadSize - 1);
        SetMem (MessageBlock, MessageBlockSize, Pad);
      }

      CopyMem (MessageBlock, HmacBuffer, BufferSize + SHA_DIGEST_LENGTH);

      //
      // AES encryption
      //
      AES_cbc_encrypt (
                       MessageBlock,
                       EcryptedBuffer,
                       (UINT32)MessageBlockSize,
                       (AES_KEY *)TlsInstance->TlsSessionContext.ClientAesKey, /// Must be initialized before encryption
                       TlsInstance->TlsSessionContext.ClientWriteIv,
                       AES_ENCRYPT
                       );
    }

    *EcryptedBufferSize = MessageBlockSize;

    FreePool (MessageBlock);
  } else {
    ASSERT (FALSE);
  }

  FreePool (HmacBuffer);

  return Status;
}

EFI_STATUS
TlsCommonDecryption (
  IN  TLS_INSTANCE  *TlsInstance,
  IN  UINT8         ContentType,
  IN  UINT8         *Buffer,
  IN  UINT16        BufferSize,
  OUT UINT8         *DeryptedBuffer,
  OUT UINT16        *DeryptedBufferSize
  )
{
  //
  // Only for block cipher(AES)
  //
  UINT8   MessageBlock[MAX_BUFFER_SIZE];
  UINT16  MessageBlockSize;
  UINT8   Pad;
  UINT16  PadSize;
  UINT16  Index;
  //
  // TLS 1.1 and 1.2 required
  //
  UINTN  IvLen;
  UINT8  *ClientMask;

  TLSRecordHeader  TempRecordHeader;

  UINT8  Hmac[SHA_DIGEST_LENGTH];

  CONST EVP_MD  *EvpMd;
  HMAC_CTX      HMacCtx;
  UINT32        HMacDataLen;
  UINT64        Sequence;

  EFI_STATUS  Status;

  ClientMask = NULL;

  Status = EFI_SUCCESS;

  if ((CompareMem (&TlsInstance->TlsSessionContext.CipherSuite, &RsaAes_128Sha, sizeof (EFI_TLS_CIPHER)) == 0) &&
      ((TlsInstance->TlsSessionContext.Version.Minor == TLS11_PROTOCOL_VERSION_MINOR) ||
       (TlsInstance->TlsSessionContext.Version.Minor == TLS12_PROTOCOL_VERSION_MINOR)))
  {
    IvLen = 128/8;
  } else {
    IvLen = 0;
  }

  MessageBlockSize = BufferSize;

  //
  // Decrypt message.
  //
  if (CompareMem (&TlsInstance->TlsSessionContext.CipherSuite, &RsaRc4_128Sha, sizeof (EFI_TLS_CIPHER)) == 0) {
    //
    // RC4 decryption
    //
    RC4 (
         &TlsInstance->TlsSessionContext.ServerRc4Key, /// Must be initialized before decryption
         BufferSize,
         Buffer,
         &DeryptedBuffer[0]
         );

    *DeryptedBufferSize = BufferSize - SHA_DIGEST_LENGTH;
  } else if (CompareMem (&TlsInstance->TlsSessionContext.CipherSuite, &RsaAes_128Sha, sizeof (EFI_TLS_CIPHER)) == 0) {
    if ((TlsInstance->TlsSessionContext.Version.Minor == TLS11_PROTOCOL_VERSION_MINOR) ||
        (TlsInstance->TlsSessionContext.Version.Minor == TLS12_PROTOCOL_VERSION_MINOR))
    {
      //
      // AES decryption
      //
      ClientMask = AllocateZeroPool (IvLen);
      ASSERT (ClientMask != NULL);
      AES_cbc_encrypt (
                       Buffer,
                       MessageBlock,
                       (UINT32)BufferSize,
                       ((AES_KEY *)TlsInstance->TlsSessionContext.ServerAesKey) + 1, /// Must be initialized before decryption
                       ClientMask,
                       AES_DECRYPT
                       );

      //
      // Get PadSize
      //
      Pad     = MessageBlock[MessageBlockSize - 1];
      PadSize = Pad + 1;
      if (PadSize >= MessageBlockSize) {
        PadSize = 0;
      } else {
        for (Index = MessageBlockSize - PadSize; Index < MessageBlockSize; Index++) {
          if (MessageBlock[Index] != Pad) {
            PadSize = 0;
            break;
          }
        }
      }

      CopyMem (&DeryptedBuffer[0], MessageBlock + IvLen, MessageBlockSize - PadSize - IvLen);
      *DeryptedBufferSize = MessageBlockSize - SHA_DIGEST_LENGTH - PadSize - (UINT16)IvLen;

      FreePool (ClientMask);
    } else {
      //
      // AES decryption
      //
      AES_cbc_encrypt (
                       Buffer,
                       MessageBlock,
                       (UINT32)BufferSize,
                       ((AES_KEY *)TlsInstance->TlsSessionContext.ServerAesKey) + 1, /// Must be initialized before decryption
                       TlsInstance->TlsSessionContext.ServerWriteIv,
                       AES_DECRYPT
                       );

      //
      // Get PadSize
      //
      Pad     = MessageBlock[MessageBlockSize - 1];
      PadSize = Pad + 1;
      if (PadSize >= MessageBlockSize) {
        PadSize = 0;
      } else {
        for (Index = MessageBlockSize - PadSize; Index < MessageBlockSize; Index++) {
          if (MessageBlock[Index] != Pad) {
            PadSize = 0;
            break;
          }
        }
      }

      CopyMem (&DeryptedBuffer[0], MessageBlock, MessageBlockSize - PadSize);
      *DeryptedBufferSize = MessageBlockSize - SHA_DIGEST_LENGTH - PadSize;
    }
  } else {
    return EFI_UNSUPPORTED;
  }

  //
  // Check HMAC for this message
  //
  TempRecordHeader.ContentType   = ContentType;
  TempRecordHeader.Version.Major = TlsInstance->TlsSessionContext.Version.Major;
  TempRecordHeader.Version.Minor = TlsInstance->TlsSessionContext.Version.Minor;
  TempRecordHeader.Length        = HTONS (*DeryptedBufferSize); /// Must change to big-endian.

  EvpMd = EVP_get_digestbyname ("SHA1"); /// HMAC-SHA1 at protecting record(Supported in TLS1.0/1.1/1.2)
  HMAC_Init (&HMacCtx, TlsInstance->TlsSessionContext.ServerWriteMacSecret, SHA_DIGEST_LENGTH, EvpMd);
  Sequence = NTOHLL (TlsInstance->TlsSessionContext.ServerSequence);
  HMAC_Update (&HMacCtx, (UINT8 *)&Sequence, sizeof (Sequence));         /// Sequence Num
  HMAC_Update (&HMacCtx, (UINT8 *)&TempRecordHeader, RECORD_HEADER_LEN); /// Record Header
  HMAC_Update (&HMacCtx, (UINT8 *)DeryptedBuffer, *DeryptedBufferSize);  /// Record Data
  HMAC_Final (&HMacCtx, (UINT8 *)&Hmac[0], &HMacDataLen);

  TlsInstance->TlsSessionContext.ServerSequence++;

  if (CompareMem (&Hmac[0], &DeryptedBuffer[*DeryptedBufferSize], SHA_DIGEST_LENGTH) == 0) {
    // DEBUG ((EFI_D_ERROR, "HMAC check - pass\n"));
  } else {
    DEBUG ((EFI_D_ERROR, "HMAC check - fail\n"));
    TlsInstance->TlsSessionState = EfiTlsSessionError;

    if (TlsInstance->TlsAlert != NULL) {
      FreePool (TlsInstance->TlsAlert);
    }

    TlsInstance->TlsAlert              = AllocateZeroPool (sizeof (TLS_ALERT));
    TlsInstance->TlsAlert->Level       = TLS_ALERT_LEVEL_FATAL;
    TlsInstance->TlsAlert->Description = TLS_ALERT_DESCRIPTION_DECRYPTION_FAILED;

    return EFI_ABORTED;
  }

  return Status;
}

EFI_STATUS
TlsCheckHandshakeFinshedmessage (
  IN TLS_INSTANCE  *TlsInstance,
  IN UINT8         *Buffer,
  IN UINT32        BufferSize
  )
{
  EFI_STATUS  Status;

  UINTN  CtxSize;

  UINT8   PlainMessage[MAX_BUFFER_SIZE];
  UINT16  PlainMessageSize;

  Status = EFI_SUCCESS;

  //
  // Initialize required key
  //
  if (CompareMem (&TlsInstance->TlsSessionContext.CipherSuite, &RsaRc4_128Sha, sizeof (EFI_TLS_CIPHER)) == 0) {
    RC4_set_key (&TlsInstance->TlsSessionContext.ServerRc4Key, 128/8, TlsInstance->TlsSessionContext.ServerWriteKey);
  } else if (CompareMem (&TlsInstance->TlsSessionContext.CipherSuite, &RsaAes_128Sha, sizeof (EFI_TLS_CIPHER)) == 0) {
    CtxSize                                     = AesGetContextSize ();
    TlsInstance->TlsSessionContext.ServerAesKey = AllocatePool (CtxSize);
    AesInit (TlsInstance->TlsSessionContext.ServerAesKey, TlsInstance->TlsSessionContext.ServerWriteKey, 128);
  } else {
    Status = EFI_UNSUPPORTED;
    return Status;
  }

  //
  // Decryption
  //
  Status = TlsCommonDecryption (
                                TlsInstance,
                                TLS_CONTENT_TYPE_HANDSHAKE,
                                Buffer, /// Not include TLSRecordHeader
                                (UINT16)BufferSize,
                                PlainMessage,
                                &PlainMessageSize
                                );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Some common check
  //
  if ((PlainMessageSize != HANDSHAKE_HEADER_LEN + 12) || \
      ((UINT8)TlsDecodeUint8 (PlainMessage, 1) != TLS_HANDSHAKE_TYPE_FINISHED))
  {
    TlsInstance->TlsSessionState = EfiTlsSessionError;

    if (TlsInstance->TlsAlert != NULL) {
      FreePool (TlsInstance->TlsAlert);
    }

    TlsInstance->TlsAlert              = AllocateZeroPool (sizeof (TLS_ALERT));
    TlsInstance->TlsAlert->Level       = TLS_ALERT_LEVEL_FATAL;
    TlsInstance->TlsAlert->Description = TLS_ALERT_DESCRIPTION_HANDSHAKE_FAILURE;

    Status = EFI_ABORTED;
    return Status;
  }

  //
  // Check verified data
  //
  TlsFinishHandshakeMessage (&TlsInstance->TlsSessionContext);
  TlsGetServerVerifyData (&TlsInstance->TlsSessionContext);
  if (CompareMem (TlsInstance->TlsSessionContext.ServerVerifyData, &PlainMessage[HANDSHAKE_HEADER_LEN], 12) == 0) {
    DEBUG ((EFI_D_ERROR, "VerifiedData check - pass\n"));
  } else {
    DEBUG ((EFI_D_ERROR, "VerifiedData check - fail\n"));
    TlsInstance->TlsSessionState = EfiTlsSessionError;

    if (TlsInstance->TlsAlert != NULL) {
      FreePool (TlsInstance->TlsAlert);
    }

    TlsInstance->TlsAlert              = AllocateZeroPool (sizeof (TLS_ALERT));
    TlsInstance->TlsAlert->Level       = TLS_ALERT_LEVEL_FATAL;
    TlsInstance->TlsAlert->Description = TLS_ALERT_DESCRIPTION_HANDSHAKE_FAILURE;

    Status = EFI_ABORTED;
    return Status;
  }

  //
  // Hash for plain text
  //
  if (!TlsInstance->TlsSessionContext.ServerHandShakeFinished) {
    TlsInstance->TlsSessionContext.ServerHandShakeFinished = TRUE;
    TlsUpdateHandshakeMessage (&TlsInstance->TlsSessionContext, (UINT8 *)&PlainMessage[0], HANDSHAKE_HEADER_LEN + 12);
  }

  return Status;
}

EFI_STATUS
TlsProcessHandshakeRecord (
  IN TLS_INSTANCE  *TlsInstance,
  IN UINT8         *Buffer,
  IN UINT16        BufferSize
  )
{
  TLSRecordHeader  *RecordHeader;
  UINT8            *BufferPtr;
  UINT8            *p;

  UINT8   HandshakeType;
  UINT32  HandShakeLength;

  UINT32    CertDataLength;
  UINT8     *ServerCert;
  UINTN     ServerCertSize;
  UINT8     *ServerCACert;
  UINTN     ServerCACertSize;
  EVP_PKEY  *EvpPubKey;
  BOOLEAN   Ret;

  p = NULL;

  ServerCert       = NULL;
  ServerCertSize   = 0;
  ServerCACert     = NULL;
  ServerCACertSize = 0;
  EvpPubKey        = NULL;

  RecordHeader = (TLSRecordHeader *)Buffer;
  BufferPtr    = (UINT8 *)(RecordHeader + 1);

  //
  // One TLS record message may have multiply handshake protocol.
  //
  while ((UINTN)BufferPtr < (UINTN)Buffer + BufferSize) {
    p               = BufferPtr;
    HandshakeType   = (UINT8)TlsDecodeUint8 (p, 1); /// HandshakeType(1), except for TLS_HANDSHAKE_TYPE_FINISHED, will check it later if needed.
    p              += 1;
    HandShakeLength = (UINT32)TlsDecodeUint8 (p, 3);  /// Length(3), except for TLS_HANDSHAKE_TYPE_FINISHED, will check it later if needed.
    p              += 3;
    switch (HandshakeType) {
      case TLS_HANDSHAKE_TYPE_HELLO_REQUEST:
        return EFI_UNSUPPORTED;
      case TLS_HANDSHAKE_TYPE_SERVER_HELLO:
        ASSERT (CompareMem (&TlsInstance->TlsSessionContext.Version, p, sizeof (EFI_TLS_VERSION)) == 0); /// Version
        p += sizeof (EFI_TLS_VERSION);
        CopyMem (&TlsInstance->TlsSessionContext.ServerRandom, p, sizeof (EFI_TLS_RANDOM)); /// Random, stored in the form of big big-endian?
        p += sizeof (EFI_TLS_RANDOM);
        CopyMem (&TlsInstance->TlsSessionContext.SessionId, p + 1, sizeof (EFI_TLS_SESSION_ID)); /// SessionIdLen + SessionId
        p = p + 1 + sizeof (EFI_TLS_SESSION_ID);
        CopyMem (&TlsInstance->TlsSessionContext.CipherSuite, p, sizeof (EFI_TLS_CIPHER)); /// CipherSuite
        p += sizeof (EFI_TLS_CIPHER);
        CopyMem (&TlsInstance->TlsSessionContext.Compression, p, sizeof (EFI_TLS_COMPRESSION));/// CompressionMethod
        p += sizeof (EFI_TLS_COMPRESSION);

        ASSERT (TlsIsValidCipherSuite (&TlsInstance->TlsSessionContext.CipherSuite, TlsInstance->TlsCipherNum, TlsInstance->TlsCipher));
        break;
      case TLS_HANDSHAKE_TYPE_CERTIFICATE:
        CertDataLength = (UINT32)TlsDecodeUint8 (p, 3); /// Length(3)
        p             += 3;

        //
        // Get required cert.
        //
        TlsGetServerCertificate (
                                 p,
                                 CertDataLength,
                                 &ServerCert,
                                 &((UINT32)ServerCertSize),
                                 &ServerCACert,
                                 &((UINT32)ServerCACertSize)
                                 );

        //
        // Get ServerRSAPubKey from ServerCert.
        //
        EvpPubKey = TlsGetPubkeyFromCertificate (ServerCert, (UINT32)ServerCertSize);
        if (EvpPubKey == NULL) {
          TlsInstance->TlsSessionState = EfiTlsSessionError;

          if (TlsInstance->TlsAlert != NULL) {
            FreePool (TlsInstance->TlsAlert);
          }

          TlsInstance->TlsAlert              = AllocateZeroPool (sizeof (TLS_ALERT));
          TlsInstance->TlsAlert->Level       = TLS_ALERT_LEVEL_FATAL;
          TlsInstance->TlsAlert->Description = TLS_ALERT_DESCRIPTION_CERTIFICATE_UNKNOWN;

          return EFI_ABORTED;
        }

        TlsInstance->TlsSessionContext.ServerRSAPubKey = EVP_PKEY_get1_RSA (EvpPubKey);

        //
        // Do some certificate verify if necessary.
        //
        if (TlsInstance->State == TLS_STATE_CONFIGED) {
          if ((TlsInstance->ClientCACert != NULL) && (ServerCert != NULL)) {
            Ret = X509VerifyCert (
                                  ServerCert,
                                  ServerCertSize,
                                  TlsInstance->ClientCACert,
                                  TlsInstance->ClientCACertSize
                                  );
            DEBUG ((EFI_D_ERROR, "X509VerifyCert server cert - 0x%x\n", Ret));

            if (!Ret) {
              TlsInstance->TlsSessionState = EfiTlsSessionError;

              if (TlsInstance->TlsAlert != NULL) {
                FreePool (TlsInstance->TlsAlert);
              }

              TlsInstance->TlsAlert              = AllocateZeroPool (sizeof (TLS_ALERT));
              TlsInstance->TlsAlert->Level       = TLS_ALERT_LEVEL_FATAL;
              TlsInstance->TlsAlert->Description = TLS_ALERT_DESCRIPTION_BAD_CERTIFICATE;

              return EFI_ABORTED;
            }
          }

          if ((ServerCACert != NULL) && (TlsInstance->ClientCert != NULL)) {
            Ret = X509VerifyCert (
                                  TlsInstance->ClientCert,
                                  TlsInstance->ClientCertSize,
                                  ServerCACert,
                                  ServerCACertSize
                                  );
            DEBUG ((EFI_D_ERROR, "X509VerifyCert client cert - 0x%x\n", Ret));

            if (!Ret) {
              TlsInstance->TlsSessionState = EfiTlsSessionError;

              if (TlsInstance->TlsAlert != NULL) {
                FreePool (TlsInstance->TlsAlert);
              }

              TlsInstance->TlsAlert              = AllocateZeroPool (sizeof (TLS_ALERT));
              TlsInstance->TlsAlert->Level       = TLS_ALERT_LEVEL_FATAL;
              TlsInstance->TlsAlert->Description = TLS_ALERT_DESCRIPTION_BAD_CERTIFICATE;

              return EFI_ABORTED;
            }
          }
        }

        break;
      case TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE:
        //
        // The ServerKeyExchange message is sent by the server only when the
        // server Certificate message (if sent) does not contain enough data
        // to allow the client to exchange a premaster secret.
        // It is not legal to send the ServerKeyExchange message for the RSA, DH_DSS, DH_RSA methods.
        //
        return EFI_UNSUPPORTED;
      case TLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
        TlsInstance->TlsSessionContext.NeedClientCertificate = TRUE;

        //
        // TODO... If version is TLS1.2, need to record the certificate verify type here(RFC 5246).
        //
        break;
      case TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE:
        if (!TlsInstance->TlsSessionContext.ServerHelloDone) {
          TlsInstance->TlsSessionContext.ServerHelloDone = TRUE;
          TlsUpdateHandshakeMessage (&TlsInstance->TlsSessionContext, BufferPtr, HANDSHAKE_HEADER_LEN + HandShakeLength);
        }

        BufferPtr += HANDSHAKE_HEADER_LEN + HandShakeLength;
        ASSERT (BufferPtr == Buffer + BufferSize);

        return EFI_SUCCESS;
      case TLS_HANDSHAKE_TYPE_CLIENT_HELLO:
        return EFI_UNSUPPORTED;
      case TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE:
        return EFI_UNSUPPORTED;
      case TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY:
        return EFI_UNSUPPORTED;
      default:
        //
        // Check the TLS_HANDSHAKE_TYPE_FINISHED message.The Finished message is one protected with the just
        // negotiated algorithms, keys, and secrets.
        //
        return TlsCheckHandshakeFinshedmessage (TlsInstance, BufferPtr, (UINT32)((UINTN)Buffer + BufferSize - (UINTN)BufferPtr));
    }

    if (!TlsInstance->TlsSessionContext.ServerHelloDone) {
      TlsUpdateHandshakeMessage (&TlsInstance->TlsSessionContext, BufferPtr, HANDSHAKE_HEADER_LEN + HandShakeLength);
    }

    BufferPtr += HANDSHAKE_HEADER_LEN + HandShakeLength;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
TlsBuildClientKeyExchange (
  IN TLS_INSTANCE  *TlsInstance,
  IN UINT8         *Buffer,
  IN UINTN         *BufferSize
  )
{
  EFI_STATUS  Status;

  TLSRecordHeader  *RecordHeader;
  UINT8            *p;

  UINTN  CertificateSize;
  UINT8  *ClientCert;
  UINTN  ClientCertSize;
  UINT8  *ClientCACert;
  UINTN  ClientCACertSize;

  UINT32  EncMsgSize;

  UINT16  ExchangeKeysSize;
  UINT16  PubKeySize;

  UINTN  CertificateVerifySize;
  UINT8  *DecMsg;
  UINTN  DecMsgSize;
  UINT8  *ClientPrivateKey;
  UINTN  ClientPrivateKeySize;

  UINTN   CtxSize;
  UINT8   Finished[HANDSHAKE_HEADER_LEN + 12];
  UINT8   CipherMessage[MAX_BUFFER_SIZE];
  UINT16  CipherMessageSize;

  Status = EFI_SUCCESS;

  CertificateSize  = 0;
  ClientCert       = NULL;
  ClientCertSize   = 0;
  ClientCACert     = NULL;
  ClientCACertSize = 0;

  EncMsgSize = 0;

  CertificateVerifySize = 0;
  DecMsg                = NULL;
  ClientPrivateKey      = NULL;
  ClientPrivateKeySize  = 0;

  if (TlsInstance->TlsSessionContext.NeedClientCertificate) {
    ClientCert           = TlsInstance->ClientCert;
    ClientCertSize       = TlsInstance->ClientCertSize;
    ClientCACert         = TlsInstance->ClientCACert;
    ClientCACertSize     = TlsInstance->ClientCACertSize;
    ClientPrivateKey     = TlsInstance->ClientPrivateKey;
    ClientPrivateKeySize = TlsInstance->ClientPrivateKeySize;

    if ((ClientCert != NULL) && (ClientCACert != NULL)) {
      CertificateSize = 3 + (3 + ClientCertSize) + (3 + ClientCACertSize);
    } else {
      CertificateSize = 0;
    }

    if (TlsInstance->TlsSessionContext.Version.Minor == TLS12_PROTOCOL_VERSION_MINOR) {
      CertificateVerifySize = sizeof (UINT16) + ClientPrivateKeySize + 2;
    } else {
      CertificateVerifySize = sizeof (UINT16) + ClientPrivateKeySize;
    }
  }

  PubKeySize = (UINT16)RSA_size (TlsInstance->TlsSessionContext.ServerRSAPubKey);
  if ((CompareMem (&TlsInstance->TlsSessionContext.CipherSuite, &RsaRc4_128Sha, sizeof (EFI_TLS_CIPHER)) == 0) ||
      (CompareMem (&TlsInstance->TlsSessionContext.CipherSuite, &RsaAes_128Sha, sizeof (EFI_TLS_CIPHER)) == 0))
  {
    ExchangeKeysSize = sizeof (UINT16) + PubKeySize;
  } else {
    ASSERT (FALSE);
    ExchangeKeysSize = 0;
  }

  //
  // Check BufferSize
  //
  if (CompareMem (&TlsInstance->TlsSessionContext.CipherSuite, &RsaRc4_128Sha, sizeof (EFI_TLS_CIPHER)) == 0) {
    if ((TlsInstance->TlsSessionContext.NeedClientCertificate ? (2 * (RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN) + CertificateSize + CertificateVerifySize) : 0) +
        RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN + ExchangeKeysSize +
        RECORD_HEADER_LEN + sizeof (TLS_CHANGE_CIPHER_SPEC) +
        RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN + sizeof (Finished) + SHA_DIGEST_LENGTH > *BufferSize)
    {
      *BufferSize = (TlsInstance->TlsSessionContext.NeedClientCertificate ? (2 * (RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN) + CertificateSize + CertificateVerifySize) : 0) +
                    (RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN + ExchangeKeysSize +
                     RECORD_HEADER_LEN + sizeof (TLS_CHANGE_CIPHER_SPEC) +
                     RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN + sizeof (Finished) + SHA_DIGEST_LENGTH);
      return EFI_BUFFER_TOO_SMALL;
    }
  } else if (CompareMem (&TlsInstance->TlsSessionContext.CipherSuite, &RsaAes_128Sha, sizeof (EFI_TLS_CIPHER)) == 0) {
    if ((TlsInstance->TlsSessionContext.Version.Minor == TLS11_PROTOCOL_VERSION_MINOR) || \
        (TlsInstance->TlsSessionContext.Version.Minor == TLS12_PROTOCOL_VERSION_MINOR))
    {
      if ((TlsInstance->TlsSessionContext.NeedClientCertificate ? (2 * (RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN) + CertificateSize + CertificateVerifySize) : 0) +
          RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN + ExchangeKeysSize +
          RECORD_HEADER_LEN + sizeof (TLS_CHANGE_CIPHER_SPEC) +
          RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN + AES_BLOCK_SIZE_CONVERT (128/8 + HANDSHAKE_HEADER_LEN + 12 + SHA_DIGEST_LENGTH) > *BufferSize)
      {
        *BufferSize = (TlsInstance->TlsSessionContext.NeedClientCertificate ? (2 * (RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN) + CertificateSize + CertificateVerifySize) : 0) +
                      (RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN + ExchangeKeysSize +
                       RECORD_HEADER_LEN + sizeof (TLS_CHANGE_CIPHER_SPEC) +
                       RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN + AES_BLOCK_SIZE_CONVERT (128/8 + HANDSHAKE_HEADER_LEN + 12 + SHA_DIGEST_LENGTH));
        return EFI_BUFFER_TOO_SMALL;
      }
    } else {
      if ((TlsInstance->TlsSessionContext.NeedClientCertificate ? (2 * (RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN) + CertificateSize + CertificateVerifySize) : 0) +
          RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN + ExchangeKeysSize +
          RECORD_HEADER_LEN + sizeof (TLS_CHANGE_CIPHER_SPEC) +
          RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN + AES_BLOCK_SIZE_CONVERT (HANDSHAKE_HEADER_LEN + 12 + SHA_DIGEST_LENGTH) > *BufferSize)
      {
        *BufferSize = (TlsInstance->TlsSessionContext.NeedClientCertificate ? (2 * (RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN) + CertificateSize + CertificateVerifySize) : 0) +
                      (RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN + ExchangeKeysSize +
                       RECORD_HEADER_LEN + sizeof (TLS_CHANGE_CIPHER_SPEC) +
                       RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN + AES_BLOCK_SIZE_CONVERT (HANDSHAKE_HEADER_LEN + 12 + SHA_DIGEST_LENGTH));
        return EFI_BUFFER_TOO_SMALL;
      }
    }
  } else {
    return EFI_UNSUPPORTED;
  }

  //
  // Gen PreMasterSecret
  //
  TlsInstance->TlsSessionContext.PreMasterSecret.Version.Major = TlsInstance->TlsSessionContext.Version.Major;
  TlsInstance->TlsSessionContext.PreMasterSecret.Version.Minor = TlsInstance->TlsSessionContext.Version.Minor;
  RAND_pseudo_bytes (&TlsInstance->TlsSessionContext.PreMasterSecret.Random[0], sizeof (TlsInstance->TlsSessionContext.PreMasterSecret.Random));

  //
  // Gen all keys by PreMasterSecret
  //
  TlsGenKeyByPreMasterSecret (&TlsInstance->TlsSessionContext);

  p = Buffer;

  //
  // 1st message - TLS_HANDSHAKE_TYPE_CERTIFICATE
  // If no suitable certificate is available, the client MUST send a certificate message containing no
  // certificates. That is, the certificate_list structure has a length of zero. If the client does not send any certificates, the
  // server MAY at its discretion either continue the handshake without client authentication, or respond with a fatal handshake_failure
  // alert. Also, if some aspect of the certificate chain was unacceptable (e.g., it was not signed by a known, trusted CA), the
  // server MAY at its discretion either continue the handshake (considering the client unauthenticated) or send a fatal alert.
  //
  if (TlsInstance->TlsSessionContext.NeedClientCertificate) {
    RecordHeader                = (TLSRecordHeader *)p;
    RecordHeader->ContentType   = TLS_CONTENT_TYPE_HANDSHAKE;
    RecordHeader->Version.Major = TlsInstance->TlsSessionContext.Version.Major;
    RecordHeader->Version.Minor = TlsInstance->TlsSessionContext.Version.Minor;
    RecordHeader->Length        = HTONS ((UINT16)(HANDSHAKE_HEADER_LEN + CertificateSize));
    p                           = (UINT8 *)(RecordHeader + 1);

    *p++ = TLS_HANDSHAKE_TYPE_CERTIFICATE;         /// HandshakeType
    p    = TlsEncodeUint8 (p, CertificateSize, 3); /// Length[3]

    if (CertificateSize != 0) {
      p = TlsEncodeUint8 (p, ((3 + ClientCertSize) + (3 + ClientCACertSize)), 3); /// Length[3]
      p = TlsEncodeUint8 (p, ClientCertSize, 3);                                  /// Length[3]
      CopyMem (p, ClientCert, ClientCertSize);                                    /// Data
      p += ClientCertSize;
      p  = TlsEncodeUint8 (p, ClientCACertSize, 3); /// Length[3]
      CopyMem (p, ClientCACert, ClientCACertSize);  /// Data
      p += ClientCACertSize;
    }

    TlsUpdateHandshakeMessage (&TlsInstance->TlsSessionContext, (UINT8 *)(RecordHeader + 1), (UINTN)p - (UINTN)(RecordHeader + 1));
  }

  //
  // 2nd message - TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE
  //
  RecordHeader                = (TLSRecordHeader *)p;
  RecordHeader->ContentType   = TLS_CONTENT_TYPE_HANDSHAKE;
  RecordHeader->Version.Major = TlsInstance->TlsSessionContext.Version.Major;
  RecordHeader->Version.Minor = TlsInstance->TlsSessionContext.Version.Minor;
  RecordHeader->Length        = HTONS ((UINT16)(HANDSHAKE_HEADER_LEN + ExchangeKeysSize));
  p                           = (UINT8 *)(RecordHeader + 1);

  *p++ = TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE;  /// HandshakeType
  p    = TlsEncodeUint8 (p, ExchangeKeysSize, 3); /// Length[3]

  p = TlsEncodeUint8 (p, PubKeySize, sizeof (UINT16)); /// en_Length[2]

  //
  // Generate ExchangeKey = Encrypt (PreMasterSecret, ServerRSAPubKey)
  //
  if ((CompareMem (&TlsInstance->TlsSessionContext.CipherSuite, &RsaRc4_128Sha, sizeof (EFI_TLS_CIPHER)) == 0) ||
      (CompareMem (&TlsInstance->TlsSessionContext.CipherSuite, &RsaAes_128Sha, sizeof (EFI_TLS_CIPHER)) == 0))
  {
    EncMsgSize = RSA_public_encrypt (
                                     sizeof (TlsInstance->TlsSessionContext.PreMasterSecret),
                                     (UINT8 *)&TlsInstance->TlsSessionContext.PreMasterSecret,
                                     p, // ExchangeKey
                                     TlsInstance->TlsSessionContext.ServerRSAPubKey,
                                     RSA_PKCS1_PADDING
                                     );
  } else {
    ASSERT (FALSE);
  }

  p += PubKeySize;

  TlsUpdateHandshakeMessage (&TlsInstance->TlsSessionContext, (UINT8 *)(RecordHeader + 1), (UINTN)p - (UINTN)(RecordHeader + 1));

  //
  // 3rd message - TLS_CHANGE_CIPHER_SPEC_TYPE_CERTIFICATE_VERIFY
  // This message is used to provide explicit verification of a client certificate. This message is only sent following a client
  // certificate that has signing capability (i.e., all certificates except those containing fixed Diffie-Hellman parameters). When
  // sent, it MUST immediately follow the client key exchange message.
  if (TlsInstance->TlsSessionContext.NeedClientCertificate) {
    ASSERT (ClientPrivateKey != NULL  && ClientPrivateKeySize != 0);
    RecordHeader                = (TLSRecordHeader *)p;
    RecordHeader->ContentType   = TLS_CONTENT_TYPE_HANDSHAKE;
    RecordHeader->Version.Major = TlsInstance->TlsSessionContext.Version.Major;
    RecordHeader->Version.Minor = TlsInstance->TlsSessionContext.Version.Minor;
    RecordHeader->Length        = HTONS ((UINT16)(HANDSHAKE_HEADER_LEN + CertificateVerifySize));
    p                           = (UINT8 *)(RecordHeader + 1);

    *p++ = TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY;        /// HandshakeType
    p    = TlsEncodeUint8 (p, CertificateVerifySize, 3); /// Length[3]

    if (TlsInstance->TlsSessionContext.Version.Minor == TLS12_PROTOCOL_VERSION_MINOR) {
      p = TlsEncodeUint8 (p, 4, 1); /// Hash Alg
      p = TlsEncodeUint8 (p, 1, 1); /// Sig Alg
    }

    p = TlsEncodeUint8 (p, ClientPrivateKeySize, 2); /// Length[2]

    //
    // Get cert verify data
    //
    TlsFinishHandshakeMessage (&TlsInstance->TlsSessionContext);
    if (TlsInstance->TlsSessionContext.Version.Minor == TLS12_PROTOCOL_VERSION_MINOR) {
      DecMsgSize = sizeof (TlsInstance->TlsSessionContext.Sha256HandshakeMessages);
      DecMsg     = AllocatePool (DecMsgSize);
      ASSERT (DecMsg != NULL);
      CopyMem (
               &DecMsg[0],
               TlsInstance->TlsSessionContext.Sha256HandshakeMessages,
               sizeof (TlsInstance->TlsSessionContext.Sha256HandshakeMessages)
               );
    } else {
      DecMsgSize = sizeof (TlsInstance->TlsSessionContext.Md5HandshakeMessages) + sizeof (TlsInstance->TlsSessionContext.Sha1HandshakeMessages);
      DecMsg     = AllocatePool (DecMsgSize);
      ASSERT (DecMsg != NULL);
      CopyMem (
               &DecMsg[0],
               TlsInstance->TlsSessionContext.Md5HandshakeMessages,
               sizeof (TlsInstance->TlsSessionContext.Md5HandshakeMessages)
               );
      CopyMem (
               &DecMsg[sizeof (TlsInstance->TlsSessionContext.Md5HandshakeMessages)],
               TlsInstance->TlsSessionContext.Sha1HandshakeMessages,
               sizeof (TlsInstance->TlsSessionContext.Sha1HandshakeMessages)
               );
    }

    if ((CompareMem (&TlsInstance->TlsSessionContext.CipherSuite, &RsaRc4_128Sha, sizeof (EFI_TLS_CIPHER)) == 0) ||
        (CompareMem (&TlsInstance->TlsSessionContext.CipherSuite, &RsaAes_128Sha, sizeof (EFI_TLS_CIPHER)) == 0))
    {
      if (0) {
        ((RSA *)ClientPrivateKey)->flags |= RSA_FLAG_NO_BLINDING;
        EncMsgSize                        = RSA_private_encrypt (
                                                                 (UINT32)DecMsgSize,
                                                                 DecMsg,
                                                                 p,
                                                                 (RSA *)ClientPrivateKey,
                                                                 RSA_PKCS1_PADDING
                                                                 );
      }

      if (1) {
        //
        // RSA_sign() privates same function with RSA_private_encrypt()
        //
        UINT8   *SigData = NULL;
        UINT32  SigLen;

        ((RSA *)ClientPrivateKey)->flags |= RSA_FLAG_NO_BLINDING;
        SigData                           = AllocatePool (ClientPrivateKeySize);
        RSA_sign (
                  (TlsInstance->TlsSessionContext.Version.Minor == TLS12_PROTOCOL_VERSION_MINOR) ? NID_sha256 : NID_md5_sha1,
                  DecMsg,
                  (UINT32)DecMsgSize,
                  SigData,
                  &SigLen,
                  (RSA *)ClientPrivateKey
                  );

        CopyMem (p, SigData, SigLen);

        FreePool (SigData);
      }

      FreePool (DecMsg);
    } else {
      ASSERT (FALSE);
    }

    p += ClientPrivateKeySize;

    TlsUpdateHandshakeMessage (&TlsInstance->TlsSessionContext, (UINT8 *)(RecordHeader + 1), (UINTN)p - (UINTN)(RecordHeader + 1));
  }

  //
  // 4th message - TLS_CHANGE_CIPHER_SPEC_TYPE_CHANGE_CIPHER_SPEC
  //
  RecordHeader                = (TLSRecordHeader *)p;
  RecordHeader->ContentType   = TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC;
  RecordHeader->Version.Major = TlsInstance->TlsSessionContext.Version.Major;
  RecordHeader->Version.Minor = TlsInstance->TlsSessionContext.Version.Minor;
  RecordHeader->Length        = HTONS (sizeof (TLS_CHANGE_CIPHER_SPEC));
  p                           = (UINT8 *)(RecordHeader + 1);

  *p++ = TLS_CHANGE_CIPHER_SPEC_TYPE_CHANGE_CIPHER_SPEC; /// Change Cipher Spec Type

  //
  // 5th message - TLS_HANDSHAKE_TYPE_FINISHED. The Finished message is the first one protected with the just
  // negotiated algorithms, keys, and secrets.
  //
  Finished[0] = TLS_HANDSHAKE_TYPE_FINISHED; /// HandshakeType
  TlsEncodeUint8 (&Finished[1], 12, 3);      /// Length[3]

  //
  // Get verify data
  //
  TlsFinishHandshakeMessage (&TlsInstance->TlsSessionContext);
  TlsGetClientVerifyData (&TlsInstance->TlsSessionContext);
  CopyMem (&Finished[HANDSHAKE_HEADER_LEN], &TlsInstance->TlsSessionContext.ClientVerifyData, 12);

  //
  // Hash for plain text
  //
  TlsUpdateHandshakeMessage (&TlsInstance->TlsSessionContext, Finished, HANDSHAKE_HEADER_LEN + 12);

  //
  // Initialize required key
  //
  if (CompareMem (&TlsInstance->TlsSessionContext.CipherSuite, &RsaRc4_128Sha, sizeof (EFI_TLS_CIPHER)) == 0) {
    RC4_set_key (&TlsInstance->TlsSessionContext.ClientRc4Key, 128/8, TlsInstance->TlsSessionContext.ClientWriteKey);
  } else if (CompareMem (&TlsInstance->TlsSessionContext.CipherSuite, &RsaAes_128Sha, sizeof (EFI_TLS_CIPHER)) == 0) {
    CtxSize                                     = AesGetContextSize ();
    TlsInstance->TlsSessionContext.ClientAesKey = AllocatePool (CtxSize);
    AesInit (TlsInstance->TlsSessionContext.ClientAesKey, TlsInstance->TlsSessionContext.ClientWriteKey, 128);
  } else {
    return EFI_UNSUPPORTED;
  }

  //
  // Encryption
  //
  Status = TlsCommonEncryption (
                                TlsInstance,
                                TLS_CONTENT_TYPE_HANDSHAKE,
                                Finished,
                                sizeof (Finished),
                                CipherMessage,
                                &CipherMessageSize
                                );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Record header
  //
  RecordHeader                = (TLSRecordHeader *)p;
  RecordHeader->ContentType   = TLS_CONTENT_TYPE_HANDSHAKE;
  RecordHeader->Version.Major = TlsInstance->TlsSessionContext.Version.Major;
  RecordHeader->Version.Minor = TlsInstance->TlsSessionContext.Version.Minor;
  RecordHeader->Length        = HTONS (CipherMessageSize);/// HandShakeHeaderLen + FinishedLen
  p                           = (UINT8 *)(RecordHeader + 1);

  //
  // Record Data
  //
  CopyMem (p, CipherMessage, CipherMessageSize);
  p += CipherMessageSize;

  //
  // BufferSize
  //
  *BufferSize = (UINTN)p - (UINTN)Buffer;

  return Status;
}

EFI_STATUS
TlsBuildChangeCipherSpec (
  IN TLS_INSTANCE  *TlsInstance,
  IN UINT8         *Buffer,
  IN UINTN         *BufferSize
  )
{
  EFI_STATUS  Status;

  TLSRecordHeader  *RecordHeader;
  UINT8            *p;

  UINTN   CtxSize;
  UINT8   Finished[HANDSHAKE_HEADER_LEN + 12];
  UINT8   CipherMessage[MAX_BUFFER_SIZE];
  UINT16  CipherMessageSize;

  Status = EFI_SUCCESS;

  //
  // Check BufferSize
  //
  if (CompareMem (&TlsInstance->TlsSessionContext.CipherSuite, &RsaRc4_128Sha, sizeof (EFI_TLS_CIPHER)) == 0) {
    if (RECORD_HEADER_LEN + sizeof (TLS_CHANGE_CIPHER_SPEC) +
        RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN + sizeof (Finished) + SHA_DIGEST_LENGTH > *BufferSize)
    {
      *BufferSize = RECORD_HEADER_LEN + sizeof (TLS_CHANGE_CIPHER_SPEC) +
                    RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN + sizeof (Finished) + SHA_DIGEST_LENGTH;
      return EFI_BUFFER_TOO_SMALL;
    }
  } else if (CompareMem (&TlsInstance->TlsSessionContext.CipherSuite, &RsaAes_128Sha, sizeof (EFI_TLS_CIPHER)) == 0) {
    if ((TlsInstance->TlsSessionContext.Version.Minor == TLS11_PROTOCOL_VERSION_MINOR) ||
        (TlsInstance->TlsSessionContext.Version.Minor == TLS12_PROTOCOL_VERSION_MINOR))
    {
      if (RECORD_HEADER_LEN + sizeof (TLS_CHANGE_CIPHER_SPEC) +
          RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN + AES_BLOCK_SIZE_CONVERT (128/8 + HANDSHAKE_HEADER_LEN + 12 + SHA_DIGEST_LENGTH) > *BufferSize)
      {
        *BufferSize = RECORD_HEADER_LEN + sizeof (TLS_CHANGE_CIPHER_SPEC) +
                      RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN + AES_BLOCK_SIZE_CONVERT (128/8 + HANDSHAKE_HEADER_LEN + 12 + SHA_DIGEST_LENGTH);
        return EFI_BUFFER_TOO_SMALL;
      }
    } else {
      if (RECORD_HEADER_LEN + sizeof (TLS_CHANGE_CIPHER_SPEC) +
          RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN + AES_BLOCK_SIZE_CONVERT (HANDSHAKE_HEADER_LEN + 12 + SHA_DIGEST_LENGTH) > *BufferSize)
      {
        *BufferSize = RECORD_HEADER_LEN + sizeof (TLS_CHANGE_CIPHER_SPEC) +
                      RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN + AES_BLOCK_SIZE_CONVERT (HANDSHAKE_HEADER_LEN + 12 + SHA_DIGEST_LENGTH);
        return EFI_BUFFER_TOO_SMALL;
      }
    }
  } else {
    return EFI_UNSUPPORTED;
  }

  RecordHeader = (TLSRecordHeader *)Buffer;
  //
  // 1st message - TLS_CHANGE_CIPHER_SPEC_TYPE_CHANGE_CIPHER_SPEC
  //
  RecordHeader->ContentType   = TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC;
  RecordHeader->Version.Major = TlsInstance->TlsSessionContext.Version.Major;
  RecordHeader->Version.Minor = TlsInstance->TlsSessionContext.Version.Minor;
  RecordHeader->Length        = HTONS (sizeof (TLS_CHANGE_CIPHER_SPEC));
  p                           = (UINT8 *)(RecordHeader + 1);

  *p++ = TLS_CHANGE_CIPHER_SPEC_TYPE_CHANGE_CIPHER_SPEC; /// Change Cipher Spec Type

  //
  // 2nd message - TLS_HANDSHAKE_TYPE_FINISHED.
  //
  Finished[0] = TLS_HANDSHAKE_TYPE_FINISHED; /// HandshakeType
  TlsEncodeUint8 (&Finished[1], 12, 3);      /// Length[3]

  //
  // Get verify data
  //
  TlsFinishHandshakeMessage (&TlsInstance->TlsSessionContext);
  TlsGetClientVerifyData (&TlsInstance->TlsSessionContext);
  CopyMem (&Finished[HANDSHAKE_HEADER_LEN], &TlsInstance->TlsSessionContext.ClientVerifyData, 12);

  //
  // Hash for plain text
  //
  TlsUpdateHandshakeMessage (&TlsInstance->TlsSessionContext, Finished, HANDSHAKE_HEADER_LEN + 12);

  //
  // Initialize required key
  //
  if (CompareMem (&TlsInstance->TlsSessionContext.CipherSuite, &RsaRc4_128Sha, sizeof (EFI_TLS_CIPHER)) == 0) {
    RC4_set_key (&TlsInstance->TlsSessionContext.ClientRc4Key, 128/8, TlsInstance->TlsSessionContext.ClientWriteKey);
  } else if (CompareMem (&TlsInstance->TlsSessionContext.CipherSuite, &RsaAes_128Sha, sizeof (EFI_TLS_CIPHER)) == 0) {
    CtxSize                                     = AesGetContextSize ();
    TlsInstance->TlsSessionContext.ClientAesKey = AllocatePool (CtxSize);
    AesInit (TlsInstance->TlsSessionContext.ClientAesKey, TlsInstance->TlsSessionContext.ClientWriteKey, 128);
  } else {
    return EFI_UNSUPPORTED;
  }

  //
  // Encryption
  //
  Status = TlsCommonEncryption (
                                TlsInstance,
                                TLS_CONTENT_TYPE_HANDSHAKE,
                                Finished,
                                sizeof (Finished),
                                CipherMessage,
                                &CipherMessageSize
                                );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Record header
  //
  RecordHeader                = (TLSRecordHeader *)p;
  RecordHeader->ContentType   = TLS_CONTENT_TYPE_HANDSHAKE;
  RecordHeader->Version.Major = TlsInstance->TlsSessionContext.Version.Major;
  RecordHeader->Version.Minor = TlsInstance->TlsSessionContext.Version.Minor;
  RecordHeader->Length        = HTONS (CipherMessageSize);/// HandShakeHeaderLen + FinishedLen
  p                           = (UINT8 *)(RecordHeader + 1);

  //
  // Record Data
  //
  CopyMem (p, CipherMessage, CipherMessageSize);
  p += CipherMessageSize;

  //
  // BufferSize
  //
  *BufferSize = (UINTN)p - (UINTN)Buffer;

  return Status;
}

EFI_STATUS
EcryptPacket (
  IN     TLS_INSTANCE           *TlsInstance,
  IN OUT EFI_TLS_FRAGMENT_DATA  **FragmentTable,
  IN     UINT32                 *FragmentCount
  )
{
  UINTN   Index;
  UINT32  BytesCopied;
  UINT32  BufferInSize;
  UINT8   *BufferIn;

  UINT8            *BufferInPtr;
  TLSRecordHeader  *RecordHeader;
  UINT16           ThisMessageSize;

  UINT8            TempBuffer[MAX_BUFFER_SIZE];
  TLSRecordHeader  *TempRecordHeader;
  UINT16           ThisCipherMessageSize;

  UINT32  BufferOutSize;
  UINT8   *BufferOut;

  EFI_STATUS  Status;

  BytesCopied  = 0;
  BufferInSize = 0;
  BufferIn     = NULL;

  BufferInPtr  = NULL;
  RecordHeader = NULL;

  TempRecordHeader = NULL;

  BufferOutSize = 0;
  BufferOut     = NULL;

  Status = EFI_SUCCESS;

  //
  // Calculate the size accroding to the fragment table.
  //
  for (Index = 0; Index < *FragmentCount; Index++) {
    BufferInSize += (*FragmentTable)[Index].FragmentLength;
  }

  //
  // Allocate buffer for processing data
  //
  BufferIn = AllocateZeroPool (BufferInSize);
  if (BufferIn == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    return Status;
  }

  //
  // Copy all TLS plain record header and payload to ProcessBuffer
  //
  for (Index = 0; Index < *FragmentCount; Index++) {
    CopyMem (
             (BufferIn + BytesCopied),
             (*FragmentTable)[Index].FragmentBuffer,
             (*FragmentTable)[Index].FragmentLength
             );
    BytesCopied += (*FragmentTable)[Index].FragmentLength;
  }

  //
  // Allocate buffer for ercypted data
  //
  BufferOut = AllocateZeroPool (MAX_BUFFER_SIZE);
  if (BufferOut == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    return Status;
  }

  /****************************************************************************Amazing Cutting line****************************************************************/
  //
  // Parsing buffer.
  //
  BufferInPtr      = BufferIn;
  TempRecordHeader = (TLSRecordHeader *)TempBuffer;
  while ((UINTN)BufferInPtr < (UINTN)BufferIn + BufferInSize) {
    RecordHeader = (TLSRecordHeader *)BufferInPtr;
    ASSERT (RecordHeader->ContentType == TLS_CONTENT_TYPE_APPLICATION_DATA);
    ThisMessageSize = RecordHeader->Length;
    Status          = TlsCommonEncryption (
                                           TlsInstance,
                                           RecordHeader->ContentType,
                                           (UINT8 *)(RecordHeader + 1),
                                           ThisMessageSize,
                                           (UINT8 *)(TempRecordHeader + 1),
                                           &ThisCipherMessageSize
                                           );
    if (EFI_ERROR (Status)) {
      return Status;
    }

    CopyMem (TempRecordHeader, RecordHeader, RECORD_HEADER_LEN);
    TempRecordHeader->Length = HTONS (ThisCipherMessageSize);
    CopyMem (&BufferOut[BufferOutSize], TempRecordHeader, RECORD_HEADER_LEN + ThisCipherMessageSize);
    BufferOutSize += RECORD_HEADER_LEN + ThisCipherMessageSize;

    BufferInPtr += RECORD_HEADER_LEN + ThisMessageSize;
  }

  /****************************************************************************Amazing Cutting line****************************************************************/

  //
  // The caller will take responsible to handle the original fragment table
  //
  *FragmentTable = AllocateZeroPool (sizeof (EFI_TLS_FRAGMENT_DATA));
  if (*FragmentTable == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    return Status;
  }

  (*FragmentTable)[0].FragmentBuffer = BufferOut;
  (*FragmentTable)[0].FragmentLength = BufferOutSize;
  *FragmentCount                     = 1;

  FreePool (BufferIn);

  return Status;
}

EFI_STATUS
DecryptPacket (
  IN     TLS_INSTANCE           *TlsInstance,
  IN OUT EFI_TLS_FRAGMENT_DATA  **FragmentTable,
  IN     UINT32                 *FragmentCount
  )
{
  UINTN   Index;
  UINT32  BytesCopied;
  UINT8   *BufferIn;
  UINT8   *BufferOut;
  UINT32  BufferInSize;
  UINT32  BufferOutSize;

  UINT8            *BufferInPtr;
  TLSRecordHeader  *RecordHeader;
  UINT16           ThisMessageSize;

  UINT8            TempBuffer[MAX_BUFFER_SIZE];
  TLSRecordHeader  *TempRecordHeader;
  UINT16           ThisPlainMessageSize;

  EFI_STATUS  Status;

  /*
  UINT64       Ticker;
  UINT64       StartTicker;
  UINT64       EndTicker;
  UINT64       StartValue;
  UINT64       EndValue;
  BOOLEAN      CountUp;
  */

  BytesCopied   = 0;
  BufferIn      = NULL;
  BufferOut     = NULL;
  BufferInSize  = 0;
  BufferOutSize = 0;

  BufferInPtr  = NULL;
  RecordHeader = NULL;

  TempRecordHeader = NULL;

  Status = EFI_SUCCESS;

  //
  // Calculate the size accroding to the fragment table.
  //
  for (Index = 0; Index < *FragmentCount; Index++) {
    BufferInSize += (*FragmentTable)[Index].FragmentLength;
  }

  //
  // Allocate buffer for processing data
  //
  BufferIn = AllocateZeroPool (BufferInSize);
  if (BufferIn == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    return Status;
  }

  //
  // Copy all TLS plain record header and payload to ProcessBuffer
  //
  for (Index = 0; Index < *FragmentCount; Index++) {
    CopyMem (
             (BufferIn + BytesCopied),
             (*FragmentTable)[Index].FragmentBuffer,
             (*FragmentTable)[Index].FragmentLength
             );
    BytesCopied += (*FragmentTable)[Index].FragmentLength;
  }

  /*
  GetPerformanceCounterProperties (&StartValue, &EndValue);
  if (EndValue >= StartValue) {
    CountUp = TRUE;
  } else {
    CountUp = FALSE;
  }

  StartTicker  = GetPerformanceCounter ();
  */
  /****************************************************************************Amazing Cutting line****************************************************************/
  //
  // Parsing buffer. Received packet may have multiply TLS record message.
  //
  BufferInPtr      = BufferIn;
  TempRecordHeader = (TLSRecordHeader *)TempBuffer;
  while ((UINTN)BufferInPtr < (UINTN)BufferIn + BufferInSize) {
    RecordHeader = (TLSRecordHeader *)BufferInPtr;
    ASSERT (RecordHeader->ContentType == TLS_CONTENT_TYPE_APPLICATION_DATA);
    ThisMessageSize = NTOHS (RecordHeader->Length);

    Status = TlsCommonDecryption (
                                  TlsInstance,
                                  RecordHeader->ContentType,
                                  (UINT8 *)(RecordHeader + 1),
                                  ThisMessageSize,
                                  (UINT8 *)(TempRecordHeader + 1),
                                  &ThisPlainMessageSize
                                  );
    if (EFI_ERROR (Status)) {
      FreePool (BufferIn);
      return Status;
    }

    CopyMem (TempRecordHeader, RecordHeader, RECORD_HEADER_LEN);
    TempRecordHeader->Length = ThisPlainMessageSize;
    BufferOutSize           += RECORD_HEADER_LEN + ThisPlainMessageSize;

    BufferInPtr      += RECORD_HEADER_LEN + ThisMessageSize;
    TempRecordHeader += RECORD_HEADER_LEN + ThisPlainMessageSize;
  }

  /****************************************************************************Amazing Cutting line****************************************************************/

  /*
  EndTicker = GetPerformanceCounter ();

  if (CountUp) {
    Ticker = EndTicker - StartTicker;
  } else {
    Ticker = StartTicker - EndTicker;
  }

  AsciiPrint (
    "\nwhile cost time:%ld us.\n",
    DivU64x64Remainder(GetTimeInNanoSecond (Ticker) , 1000ULL, NULL)
    );
  */
  FreePool (BufferIn);

  BufferOut = AllocateZeroPool (BufferOutSize);
  if (BufferOut == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    return Status;
  }

  //
  // The caller will take responsible to handle the original fragment table
  //
  *FragmentTable = AllocateZeroPool (sizeof (EFI_TLS_FRAGMENT_DATA));
  if (*FragmentTable == NULL) {
    FreePool (BufferOut);
    Status = EFI_OUT_OF_RESOURCES;
    return Status;
  }

  CopyMem (BufferOut, &TempBuffer[0], BufferOutSize);

  (*FragmentTable)[0].FragmentBuffer = BufferOut;
  (*FragmentTable)[0].FragmentLength = BufferOutSize;
  *FragmentCount                     = 1;

  return Status;
}

EFI_STATUS
CreateAlertNotify (
  IN     TLS_INSTANCE  *TlsInstance,
  IN OUT UINT8         *Buffer,
  IN OUT UINTN         *BufferSize
  )
{
  EFI_STATUS  Status;

  UINT8   Alert[sizeof (TLS_ALERT)];
  UINT8   CipherMessage[MAX_BUFFER_SIZE];
  UINT16  CipherMessageSize;

  TLSRecordHeader  *RecordHeader;

  Status = EFI_SUCCESS;

  //
  // Check BufferSize
  //
  if (CompareMem (&TlsInstance->TlsSessionContext.CipherSuite, &RsaRc4_128Sha, sizeof (EFI_TLS_CIPHER)) == 0) {
    if (RECORD_HEADER_LEN + sizeof (TLS_ALERT) + SHA_DIGEST_LENGTH > *BufferSize) {
      *BufferSize = RECORD_HEADER_LEN + sizeof (TLS_ALERT) + SHA_DIGEST_LENGTH;
      return EFI_BUFFER_TOO_SMALL;
    }
  } else if (CompareMem (&TlsInstance->TlsSessionContext.CipherSuite, &RsaAes_128Sha, sizeof (EFI_TLS_CIPHER)) == 0) {
    if ((TlsInstance->TlsSessionContext.Version.Minor == TLS11_PROTOCOL_VERSION_MINOR) ||
        (TlsInstance->TlsSessionContext.Version.Minor == TLS12_PROTOCOL_VERSION_MINOR))
    {
      if (RECORD_HEADER_LEN + AES_BLOCK_SIZE_CONVERT (128/8 + sizeof (TLS_ALERT) + SHA_DIGEST_LENGTH) > *BufferSize) {
        *BufferSize = RECORD_HEADER_LEN + AES_BLOCK_SIZE_CONVERT (128/8 + sizeof (TLS_ALERT) + SHA_DIGEST_LENGTH);
        return EFI_BUFFER_TOO_SMALL;
      }
    } else {
      if (RECORD_HEADER_LEN +  AES_BLOCK_SIZE_CONVERT (sizeof (TLS_ALERT) + SHA_DIGEST_LENGTH) > *BufferSize) {
        *BufferSize = RECORD_HEADER_LEN + AES_BLOCK_SIZE_CONVERT (sizeof (TLS_ALERT) + SHA_DIGEST_LENGTH);
        return EFI_BUFFER_TOO_SMALL;
      }
    }
  } else {
    return EFI_UNSUPPORTED;
  }

  //
  // Alert data
  //
  Alert[0] = TlsInstance->TlsAlert->Level;
  Alert[1] = TlsInstance->TlsAlert->Description;

  //
  // Encryption
  //
  Status = TlsCommonEncryption (
                                TlsInstance,
                                TLS_CONTENT_TYPE_ALERT,
                                Alert,
                                sizeof (Alert),
                                CipherMessage,
                                &CipherMessageSize
                                );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Record header
  //
  RecordHeader                = (TLSRecordHeader *)Buffer;
  RecordHeader->ContentType   = TLS_CONTENT_TYPE_ALERT;
  RecordHeader->Version.Major = TlsInstance->TlsSessionContext.Version.Major;
  RecordHeader->Version.Minor = TlsInstance->TlsSessionContext.Version.Minor;
  RecordHeader->Length        = HTONS (CipherMessageSize);

  //
  // Record Data
  //
  CopyMem ((UINT8 *)(RecordHeader + 1), CipherMessage, CipherMessageSize);

  //
  // BufferSize
  //
  *BufferSize = RECORD_HEADER_LEN +  CipherMessageSize;

  if (TlsInstance->TlsAlert->Level == TLS_ALERT_LEVEL_FATAL) {
    TlsCleanSessionContext (&TlsInstance->TlsSessionContext);
  }

  return Status;
}

EFI_STATUS
CreateResponsePacket (
  IN     TLS_INSTANCE  *TlsInstance,
  IN     UINT8         *BufferIn,
  IN     UINTN         BufferInSize,
  IN OUT UINT8         *BufferOut,
  IN OUT UINTN         *BufferOutSize
  )
{
  EFI_STATUS  Status;

  UINT8            *BufferInPtr;
  TLSRecordHeader  *RecordHeader;

  UINT8   PlainMessage[MAX_BUFFER_SIZE];
  UINT16  PlainMessageSize;

  Status = EFI_SUCCESS;

  //
  // Parsing received packet. Received packet may have multiply TLS record message.
  //
  BufferInPtr = BufferIn;
  while ((UINTN)BufferInPtr < (UINTN)BufferIn + BufferInSize) {
    RecordHeader = (TLSRecordHeader *)BufferInPtr;

    if (RecordHeader->ContentType == TLS_CONTENT_TYPE_HANDSHAKE) {
      //
      // Process Handshake message
      //
      Status = TlsProcessHandshakeRecord (TlsInstance, (UINT8 *)RecordHeader, RECORD_HEADER_LEN + NTOHS (RecordHeader->Length));
      if (EFI_ERROR (Status)) {
        break;
      }

      BufferInPtr += RECORD_HEADER_LEN + NTOHS (RecordHeader->Length);
    } else if (RecordHeader->ContentType == TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC) {
      //
      // Parsing change cipher spec message
      //
      if (((TLS_CHANGE_CIPHER_SPEC *)(RecordHeader + 1))->Type != TLS_CHANGE_CIPHER_SPEC_TYPE_CHANGE_CIPHER_SPEC) {
        TlsInstance->TlsSessionState = EfiTlsSessionError;

        if (TlsInstance->TlsAlert != NULL) {
          FreePool (TlsInstance->TlsAlert);
        }

        TlsInstance->TlsAlert              = AllocateZeroPool (sizeof (TLS_ALERT));
        TlsInstance->TlsAlert->Level       = TLS_ALERT_LEVEL_FATAL;
        TlsInstance->TlsAlert->Description = TLS_ALERT_DESCRIPTION_UNEXPECTED_MESSAGE;

        break;
      }

      BufferInPtr += RECORD_HEADER_LEN + NTOHS (RecordHeader->Length);
    } else if (RecordHeader->ContentType == TLS_CONTENT_TYPE_ALERT) {
      //
      // Decrypt alert message
      //
      Status = TlsCommonDecryption (
                                    TlsInstance,
                                    TLS_CONTENT_TYPE_ALERT,
                                    (UINT8 *)(RecordHeader + 1), /// Not include TLSRecordHeader
                                    NTOHS (RecordHeader->Length),
                                    PlainMessage,
                                    &PlainMessageSize
                                    );
      if (EFI_ERROR (Status)) {
        break;
      }

      ASSERT (PlainMessageSize == sizeof (TLS_ALERT));

      //
      // Upon receipt of an fatal alert message, both parties immediately close the connection.
      // Servers and clients are required to forget any session-identifiers, keys, and secrets associated with a failed connection.
      // If an alert with a level of warning is received, the receiving party may decide at its discretion whether to treat this as a fatal error or not.
      //
      if (((TLS_ALERT *)PlainMessage)->Level == TLS_ALERT_LEVEL_FATAL) {
        TlsInstance->TlsSessionState = EfiTlsSessionError;

        if (TlsInstance->TlsAlert != NULL) {
          FreePool (TlsInstance->TlsAlert);
        }

        TlsInstance->TlsAlert              = AllocateZeroPool (sizeof (TLS_ALERT));
        TlsInstance->TlsAlert->Level       = TLS_ALERT_LEVEL_FATAL;
        TlsInstance->TlsAlert->Description = TLS_ALERT_DESCRIPTION_CLOSE_NOTIFY;
        break;
      }

      BufferInPtr += RECORD_HEADER_LEN + NTOHS (RecordHeader->Length);
    } else {
      //
      // Unsupported message
      //
      return EFI_UNSUPPORTED;
    }
  } /// End while

  //
  // Build BufferOut
  //
  if (TlsInstance->TlsSessionState == EfiTlsSessionError) {
    if (TlsInstance->TlsAlert == NULL) {
      TlsInstance->TlsAlert              = AllocateZeroPool (sizeof (TLS_ALERT));
      TlsInstance->TlsAlert->Level       = TLS_ALERT_LEVEL_FATAL;
      TlsInstance->TlsAlert->Description = TLS_ALERT_DESCRIPTION_CLOSE_NOTIFY;
    }

    CreateAlertNotify (TlsInstance, BufferOut, BufferOutSize);

    return Status;
  }

  if (!EFI_ERROR (Status)) {
    if (TlsInstance->TlsSessionContext.ServerHelloDone &&
        !TlsInstance->TlsSessionContext.ClientHandShakeFinished &&
        !TlsInstance->TlsSessionContext.ServerHandShakeFinished
        )
    {
      //
      // Build Client KeyExchange.
      //
      Status = TlsBuildClientKeyExchange (TlsInstance, BufferOut, BufferOutSize);
      if (!EFI_ERROR (Status)) {
        TlsInstance->TlsSessionContext.ClientHandShakeFinished = TRUE;
      }
    } else if (TlsInstance->TlsSessionContext.ServerHelloDone &&
               !TlsInstance->TlsSessionContext.ClientHandShakeFinished &&
               TlsInstance->TlsSessionContext.ServerHandShakeFinished
               )
    {
      //
      // Build Change CipherSpec. (Resume Session!!!)
      //
      ASSERT (TlsInstance->TlsResumeSessionID != NULL && CompareMem (&TlsInstance->TlsSessionContext.SessionId, TlsInstance->TlsResumeSessionID, sizeof (EFI_TLS_SESSION_ID)) == 0);
      Status = TlsBuildChangeCipherSpec (TlsInstance, BufferOut, BufferOutSize);
      if (!EFI_ERROR (Status)) {
        TlsInstance->TlsSessionContext.ClientHandShakeFinished = TRUE;
      }
    } else {
      //
      // TlsInstance->TlsSessionContext.ClientHandShakeFinished == TRUE or ServerHelloDone not received, means no packet out!!!We just handle received packet.
      //
      *BufferOutSize = 0;
    }
  } else {
    *BufferOutSize = 0;
  }

  //
  // All HandShake finished, set TlsInstance->TlsSessionState to EfiTlsSessionDataTransferring.
  //
  if (TlsInstance->TlsSessionContext.ClientHandShakeFinished && TlsInstance->TlsSessionContext.ServerHandShakeFinished) {
    TlsInstance->TlsSessionState = EfiTlsSessionDataTransferring;
  }

  return Status;
}

EFI_STATUS
CreateClientHello (
  IN     TLS_INSTANCE  *TlsInstance,
  IN OUT UINT8         *Buffer,
  IN OUT UINTN         *BufferSize
  )
{
  TLSRecordHeader  *RecordHeader;
  UINT8            *p;

  UINT32  GmtUnixTime;

  UINT16  ClientHelloLen;
  UINT16  SessionIDLen;
  UINT16  CipherSuiteLen;
  UINT16  CompressionMethodLen;

  ClientHelloLen       = 0;
  SessionIDLen         = 0;
  CipherSuiteLen       = 0;
  CompressionMethodLen = 0;

  if (TlsInstance->TlsResumeSessionID != NULL) {
    SessionIDLen = sizeof (EFI_TLS_SESSION_ID);
  }

  CipherSuiteLen       = (TlsInstance->TlsCipherNum) * sizeof (EFI_TLS_CIPHER);
  CompressionMethodLen = (TlsInstance->TlsCompressionNum) * sizeof (EFI_TLS_COMPRESSION);

  ClientHelloLen = sizeof (EFI_TLS_VERSION) + sizeof (EFI_TLS_RANDOM) + (1 + SessionIDLen) + (2 + CipherSuiteLen) + (1 + CompressionMethodLen);

  if ((UINTN)(RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN + ClientHelloLen) > *BufferSize) {
    *BufferSize = RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN + ClientHelloLen;
    return EFI_BUFFER_TOO_SMALL;
  }

  //
  // Gen random
  //
  TlsInstance->TlsSessionContext.ClientRandom.GmtUnixTime = 0;
  time (&GmtUnixTime);
  CopyMem (&TlsInstance->TlsSessionContext.ClientRandom.GmtUnixTime, &GmtUnixTime, sizeof (GmtUnixTime));
  TlsInstance->TlsSessionContext.ClientRandom.GmtUnixTime = HTONL (TlsInstance->TlsSessionContext.ClientRandom.GmtUnixTime); /// stored in the form of big-endian
  RAND_pseudo_bytes (&TlsInstance->TlsSessionContext.ClientRandom.RandomBytes[0], sizeof (TlsInstance->TlsSessionContext.ClientRandom.RandomBytes));

  TlsInitHandshakeMessage (&TlsInstance->TlsSessionContext);

  //
  // Record header
  //
  RecordHeader                = (TLSRecordHeader *)Buffer; /// Record header
  RecordHeader->ContentType   = TLS_CONTENT_TYPE_HANDSHAKE;
  RecordHeader->Version.Major = TlsInstance->TlsSessionContext.Version.Major;
  RecordHeader->Version.Minor = TlsInstance->TlsSessionContext.Version.Minor;
  RecordHeader->Length        = HTONS (HANDSHAKE_HEADER_LEN + ClientHelloLen);

  //
  // ClientHello contents
  //
  p    = (UINT8 *)(RecordHeader + 1);                                             /// (HandShake header + ClientHello contents.)
  *p++ = TLS_HANDSHAKE_TYPE_CLIENT_HELLO;                                         /// HandshakeType
  p    = TlsEncodeUint8 (p, ClientHelloLen, 3);                                   /// Length[3]
  CopyMem (p, &TlsInstance->TlsSessionContext.Version, sizeof (EFI_TLS_VERSION)); /// EFI_TLS_VERSION
  p += sizeof (EFI_TLS_VERSION);
  CopyMem (p, &TlsInstance->TlsSessionContext.ClientRandom, sizeof (EFI_TLS_RANDOM)); /// EFI_TLS_RANDOM
  p += sizeof (EFI_TLS_RANDOM);
  p  = TlsEncodeUint8 (p, SessionIDLen, 1); /// SessionIDLen;
  if (SessionIDLen != 0) {
    CopyMem (p, TlsInstance->TlsResumeSessionID, SessionIDLen); /// EFI_TLS_SESSION_ID
    p += SessionIDLen;
  }

  p = TlsEncodeUint8 (p, CipherSuiteLen, 2); /// CipherSuiteLen;
  if (CipherSuiteLen != 0) {
    CopyMem (p, TlsInstance->TlsCipher, CipherSuiteLen); /// EFI_TLS_CIPHER
    p += CipherSuiteLen;
  }

  p = TlsEncodeUint8 (p, CompressionMethodLen, 1); /// CompressionMethodLen;
  if (CompressionMethodLen != 0) {
    CopyMem (p, TlsInstance->TlsCompression, CompressionMethodLen); /// EFI_TLS_COMPRESSION
    p += CompressionMethodLen;
  }

  ASSERT (p == Buffer + RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN + ClientHelloLen);

  *BufferSize = RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN + ClientHelloLen;

  TlsUpdateHandshakeMessage (&TlsInstance->TlsSessionContext, Buffer + RECORD_HEADER_LEN, HANDSHAKE_HEADER_LEN + ClientHelloLen);

  return EFI_SUCCESS;
}
