import 'dart:async';
import 'dart:typed_data';

import '../crypto_algorithm.dart';
import '../encrypted_data_key.dart';
import '../material/cryptographic_material.dart';

/// A [Keyring] typically holds, or provides access to, a single wrapping key.
/// See [wrapping key](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#master-key)
///
/// [Keyring]s are responsible for the generation, encryption,
/// and decryption of data keys.
///
/// [Keyring]s have a 'namespace' that identifies the grouping
/// or categorization for the wrapping keys that the keyring can access.
/// Some namespaces, such as 'aws-kms', are reserved for certain [Keyring]
/// subclasses.
///
/// [Keyring]s may have a 'name' that identifies a single wrapping key
/// within a key namespace.
///
/// Multi [Keyring] subclasses provide access to multiple wrapping keys
/// simultaneously allowing encryption under multiple wrapping keys and
/// decryption by any of the supplied keys.
abstract class Keyring {
  // Specification here: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md

  // needs string namespace
  // needs string name
  // needs The key provider ID MUST be a binary value and SHOULD be equal to a UTF-8 encoding of the key namespace.
  //
  // This value MUST NOT be "aws-kms" unless this encrypted data key was produced by the AWS KMS Keyring.
  //The key provider info MUST be a binary value and SHOULD be equal to a UTF-8 encoding of the key name.

  //Supported Keyrings
  // AWS KMS Keyring
  // Multi-Keyring
  // Raw AES Keyring
  // Raw RSA Keyring

  //OnEncrypt
  // This interface takes encryption materials as input and MAY modify it with any of the following behaviors:
  //
  // Generate data key
  // Encrypt data key

  //If the encryption materials do not contain a plaintext data key, OnEncrypt MAY generate a data key.
  // If the encryption materials contain a plaintext data key, OnEncrypt MUST NOT generate a data key.

  //If the encryption materials contain a plaintext data key, OnEncrypt MAY encrypt a data key.
  // If the encryption materials do not contain a plaintext data key, OnEncrypt MUST NOT encrypt a data key.

  //OnDecrypt
  // This interface takes decryption materials and a list of encrypted data keys as input and MAY modify it with the following behavior:
  //
  // Decrypt data key

  Keyring(this.namespace, this.name);

  /// [Keyring]s have a [namespace] that identifies the grouping
  /// or categorization for the wrapping keys that the keyring can access.
  /// Some namespaces, such as 'aws-kms', are reserved for certain [Keyring]
  /// subclasses.
  final String namespace;

  /// [Keyring]s may have a [name] that identifies a single wrapping key
  /// within a key namespace.
  final String name;

  FutureOr<void> onEncrypt(EncryptionMaterials materials);

  FutureOr<Uint8List> onDecrypt(
    CryptoAlgorithm algorithm,
    List<EncryptedDataKey> encryptedDataKeys,
    Map<String, String> encryptionContext,
  );
}

abstract class PointyKeyCipher {
  EncryptedDataKey encryptKey(
    Uint8List key,
    String keyName,
    String keyNamespace,
    Map<String, String> encryptionContext,
  );

  Uint8List decryptKey(
    final EncryptedDataKey edk,
    final String keyName,
    final Map<String, String> encryptionContext,
  );
}
