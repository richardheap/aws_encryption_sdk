import 'dart:async';
import 'dart:typed_data';

import '../crypto_algorithm.dart';
import '../encrypted_data_key.dart';
import '../exception/exceptions.dart';
import '../material/cryptographic_material.dart';
import 'keyring.dart';

/// A Multikeyring wraps multiple regular Keyrings.
///
/// On encryption, the randomly-chosen data key is wrapped with each of the
/// contained key rings and the resulting encrypted data keys are stored in the
/// ciphertext header.
///
/// On decryption, this keyring checks whether any of its contained key rings
/// can decrypt any of the encrypted data keys. As long as one keyring can
/// decrypt the data key, the decryption of the ciphertext proceeds.
class MultiKeyring extends Keyring {
  /// Constructs a multi key keyring.
  ///
  /// If supplied, the [generatorKeyring] has the special role, on encryption,
  /// to generate the random data key. Otherwise, one of the other key rings
  /// is used.
  ///
  /// Provide at least one key ring in [childKeyrings].
  MultiKeyring({
    Keyring? generatorKeyring,
    required List<Keyring> childKeyrings,
  })  : _generatorKeyring = generatorKeyring,
        _childKeyrings = childKeyrings,
        super('', '') {
    if (generatorKeyring == null && (childKeyrings).isEmpty) {
      throw ArgumentError('no key rings supplied');
    }
  }

  final Keyring? _generatorKeyring;
  final List<Keyring> _childKeyrings;

  @override
  FutureOr<Uint8List> onDecrypt(
    CryptoAlgorithm algorithm,
    List<EncryptedDataKey> encryptedDataKeys,
    Map<String, String> encryptionContext,
  ) async {
    final sb = StringBuffer();
    if (_generatorKeyring != null) {
      try {
        return await _generatorKeyring!.onDecrypt(
          algorithm,
          encryptedDataKeys,
          encryptionContext,
        );
      } catch (e) {
        sb.writeln(e);
      }
    }

    for (final keyring in _childKeyrings) {
      try {
        return await keyring.onDecrypt(
          algorithm,
          encryptedDataKeys,
          encryptionContext,
        );
      } catch (e) {
        sb.writeln(e);
      }
    }

    throw CannotUnwrapDataKeyException(sb.toString());
  }

  @override
  FutureOr<void> onEncrypt(EncryptionMaterials materials) async {
    if (materials.plaintextDataKey != null) {
      throw StateError(
        'encryption materials already include a plaintext data key',
      );
    }

    await _generatorKeyring?.onEncrypt(materials);

    if (materials.plaintextDataKey == null) {
      throw StateError(
        'encryption materials missing a plaintext data key',
      );
    }

    for (final keyring in _childKeyrings) {
      await keyring.onEncrypt(materials);
    }
  }
}
