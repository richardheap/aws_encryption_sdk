import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:aws_kms_api/kms-2014-11-01.dart';

import '../crypto_algorithm.dart';
import '../encrypted_data_key.dart';
import '../exception/exceptions.dart';
import '../material/cryptographic_material.dart';
import '../model/key_blob.dart';
import '../util/arn.dart';
import '../util/random.dart';
import 'keyring.dart';

/// A [Keyring] that provides an AWS KMS symmetric key.
///
/// In other implementations, on decryption, the key ring uses the ARN
/// stored in the ciphertext to locate the ARN. This implementation works
/// in what other implementations call 'strict' mode. The ARN supplied
/// to the key ring must match the ARN in the ciphertext.
///
/// In other words, supply the same ARN when encrypting and decrypting under
/// a particular AWS KMS key.
class AwsKmsKeyring extends Keyring {
  /// Constructs a [Keyring] for an AWS KMS symmetric key.
  ///
  /// Supply the full ARN (vs. id, etc.) of the AWS key in [_arn].
  AwsKmsKeyring(this._arn)
      : _region = Arn.fromString(_arn).region,
        super('aws-kms', '');

  // todo credential options

  final String _region;
  final String _arn; // todo - allow list?

  @override
  FutureOr<Uint8List> onDecrypt(
    CryptoAlgorithm algorithm,
    List<EncryptedDataKey> encryptedDataKeys,
    Map<String, String> encryptionContext,
  ) async {
    // search for an encrypted key we can decrypt
    final sb = StringBuffer();
    for (final edk in encryptedDataKeys) {
      try {
        if (edk.providerId == namespace && edk.providerInfoString == _arn) {
          final kms = KMS(region: _region);

          final response = await kms.decrypt(
            ciphertextBlob: edk.encryptedDataKey,
            keyId: _arn,
            encryptionContext: encryptionContext,
          );

          kms.close();

          return response.plaintext!;
        }
      } catch (e) {
        sb.writeln(e.toString());
      }
    }
    throw CannotUnwrapDataKeyException(sb.toString());
  }

  @override
  FutureOr<void> onEncrypt(EncryptionMaterials materials) async {
    materials.plaintextDataKey ??=
        makeRandom(materials.algorithm.dataKeyLength);

    final kms = KMS(region: _region);

    final response = await kms.encrypt(
      keyId: _arn,
      plaintext: materials.plaintextDataKey!,
      encryptionContext: materials.encryptionContext,
      encryptionAlgorithm: EncryptionAlgorithmSpec.symmetricDefault,
    );

    kms.close();

    if (response.ciphertextBlob == null) {
      return null;
    }

    materials.encryptedDataKeys.add(KeyBlob(
      utf8.encode(namespace) as Uint8List,
      utf8.encode(response.keyId ?? _arn) as Uint8List,
      response.ciphertextBlob!,
    ));
  }
}
