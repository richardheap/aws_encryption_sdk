import 'dart:typed_data';

import '../crypto_algorithm.dart';
import '../internal/trailing_signature_algorithm.dart';
import '../model/key_blob.dart';

// Encryption materials are a structure containing materials needed for encryption. This structure MAY include any of the following fields:
//
// Algorithm Suite
// Encrypted Data Keys
// Encryption Context
// Plaintext Data Key
// Signing Key

// Decryption materials are a structure containing materials needed for decryption. This structure MAY include any of the following fields:
//
// Algorithm Suite
// Encryption Context
// Plaintext Data Key
// Verification Key

class EncryptionMaterials {
  EncryptionMaterials(
    this.algorithm,
    this.encryptionContext,
    this.trailingSignatureAlgorithm,
  );

  final CryptoAlgorithm algorithm;

  final Map<String, String> encryptionContext;

  final TrailingSignatureAlgorithm? trailingSignatureAlgorithm;

  //PrivateKey? trailingSignatureKey;

  Uint8List? plaintextDataKey;

  final encryptedDataKeys = <KeyBlob>[];
}

class DecryptionMaterials {
  DecryptionMaterials(
    this.unencryptedDataKey,
    this.trailingSignatureAlgorithm,
  );

  Uint8List unencryptedDataKey;

  final TrailingSignatureAlgorithm? trailingSignatureAlgorithm;
}
