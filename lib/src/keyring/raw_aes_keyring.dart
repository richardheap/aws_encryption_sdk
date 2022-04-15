import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import '../crypto_algorithm.dart';
import '../encrypted_data_key.dart';
import '../exception/exceptions.dart';
import '../internal/encryption_context_codec.dart';
import '../internal/gcm.dart';
import '../material/cryptographic_material.dart';
import '../model/key_blob.dart';
import '../util/random.dart';
import '../util/uint8list_compare.dart';
import '../wrapping_algorithm.dart';
import 'keyring.dart';

/// A [Keyring] that provides an AES key of 128, 192 or 256 bits.
class RawAesKeyring extends Keyring {
  /// Constructs a [Keyring] for a symmetrical AES wrapping key of
  /// 128, 192 or 256 bits.
  ///
  /// [namespace] is a non-secret name to describe the group of keys, and
  /// must not be a reserved work (e.g. aws-kms) and [name] is this particular
  /// key's non-secret name.
  ///
  /// [key] is a byte list of the appropriate length (16, 24 or 32 byes), which
  /// must match the [WrappingAlgorithm] specified in [wrappingAlgorithm]. For
  /// an AES key it must be one of the wrapping algorithms starting with 'aes'.
  RawAesKeyring(
    String namespace,
    String name,
    Uint8List key,
    WrappingAlgorithm wrappingAlgorithm,
  ) : super(namespace, name) {
    _keyCipher = AesKeyCipher(key.sublist(0));
    _keyNameBytes = utf8.encode(name) as Uint8List;
    if (key.length != wrappingAlgorithm.keySizeBytes) {
      throw ArgumentError(
        'AES key length does not match wrapping algorithm',
      );
    }
    if (namespace == 'aws-kms') {
      throw ArgumentError('aws-kms is a reserved name');
    }
  }

  late AesKeyCipher _keyCipher;
  late Uint8List _keyNameBytes;

  @override
  FutureOr<Uint8List> onDecrypt(
    CryptoAlgorithm algorithm,
    List<EncryptedDataKey> encryptedDataKeys,
    Map<String, String> encryptionContext,
  ) {
    // search for an encrypted key we can decrypt
    final sb = StringBuffer();
    for (final edk in encryptedDataKeys) {
      try {
        if (edk.providerId == namespace &&
            prefixCompare(edk.providerInformation, _keyNameBytes)) {
          return _keyCipher.decryptKey(edk, name, encryptionContext);
        }
      } catch (e) {
        sb.writeln(e.toString());
      }
    }
    throw CannotUnwrapDataKeyException(sb.toString());
  }

  @override
  FutureOr<void> onEncrypt(EncryptionMaterials materials) {
    materials.plaintextDataKey ??=
        makeRandom(materials.algorithm.dataKeyLength);

    if (materials.plaintextDataKey != null) {
      materials.encryptedDataKeys.add(
        _keyCipher.encryptKey(
          materials.plaintextDataKey!,
          name,
          namespace,
          materials.encryptionContext,
        ) as KeyBlob,
      );
    }
  }
}

class AesKeyCipher extends PointyKeyCipher {
  final Uint8List _wrappingKey;

  AesKeyCipher(this._wrappingKey);

  @override
  EncryptedDataKey encryptKey(
    Uint8List key,
    String keyName,
    String keyNamespace,
    Map<String, String> encryptionContext,
  ) {
    final nonce = makeRandom(12);

    final encryptedKey = encrypt(
      _wrappingKey,
      nonce,
      serializeEncryptionContext(encryptionContext),
      key,
    );

    final spec = Uint8List(20);
    spec.buffer.asByteData()
      ..setInt32(0, 128) // tag length
      ..setInt32(4, 12); // nonce length
    spec.setRange(8, 20, nonce);

    final providerInfo = BytesBuilder()
      ..add(utf8.encode(keyName))
      ..add(spec);

    return KeyBlob(
      utf8.encode(keyNamespace) as Uint8List,
      providerInfo.toBytes(),
      encryptedKey,
    );
  }

  @override
  Uint8List decryptKey(
    final EncryptedDataKey edk,
    final String keyName,
    final Map<String, String> encryptionContext,
  ) {
    final keyNameBytes = utf8.encode(keyName) as Uint8List;
    final providerInfo = edk.providerInformation;
    if (providerInfo.length != keyNameBytes.length + 20) {
      throw AwsCryptoException(
        'Algorithm specification was an invalid data size',
      );
    }
    final spec = providerInfo.sublist(keyNameBytes.length);
    final bd = spec.buffer.asByteData();
    final nonce = spec.sublist(8);
    if (bd.getInt32(0) != 128 || bd.getInt32(4) != 12) {
      throw AwsCryptoException('invalid tag or nonce length');
    }

    try {
      return decrypt(
        _wrappingKey,
        nonce,
        serializeEncryptionContext(encryptionContext),
        edk.encryptedDataKey,
      );
    } on BadCiphertextException catch (e) {
      throw BadCiphertextException('failed to unwrap key: ${e.msg}');
    }
  }
}
