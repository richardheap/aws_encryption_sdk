import 'dart:typed_data';

import 'crypto_algorithm.dart';
import 'crypto_result.dart';
import 'exception/exceptions.dart';
import 'internal/decryption_handler.dart';
import 'internal/encryption_handler.dart';
import 'keyring/keyring.dart';
import 'material/default_materials_manager.dart';
import 'model/ciphertext_headers.dart';
import 'util/reader.dart';

/// The reusable main engine class. Provides the ability to override the
/// defaults for encryption suite and frame size
class AwsCrypto {
  /// Constructs an instance of the engine, using the defaults.
  ///
  /// The algorithm suite controls encryption features such as signing.
  /// Use the default unless you understand the differences. (Note that
  /// only version 2 algorithms are supported by this implementation.
  ///
  /// The [encryptionFrameSize] controls the chunking of blocks inside the
  /// ciphertext.
  ///
  /// If [maxEncryptionDataKeys] is specified it limits the number of data
  /// keys allowed in ciphertext.
  AwsCrypto({
    CryptoAlgorithm encryptionAlgorithm =
        CryptoAlgorithm.algAes256GcmHkdfSha512CommitKeyEcdsaP384,
    int encryptionFrameSize = 4096,
    int maxEncryptedDataKeys = 0,
  })  : _encryptionAlgorithm = encryptionAlgorithm,
        _encryptionFrameSize = encryptionFrameSize,
        _maxEncryptedDataKeys = maxEncryptedDataKeys {
    if (_encryptionFrameSize < 512) {
      throw ArgumentError('minimum frame size is 512');
    }
  }

  final CryptoAlgorithm _encryptionAlgorithm;
  final int _encryptionFrameSize;
  final int _maxEncryptedDataKeys;

  /// Encrypts the [data] under the wrapping key(s).
  ///
  /// Supply either a [Keyring] or a customised [MaterialsManager].
  /// If a [Keyring] is supplied, the SDK uses the [DefaultMaterialsManager].
  ///
  /// Optionally, supply a set of non-secret key-value pairs in
  /// [encryptionContext] to be included in, and cryptographically bound to,
  /// the ciphertext.
  ///
  /// Returns the result as a [CryptoResult].
  Future<CryptoResult> encryptData({
    Keyring? keyring,
    MaterialsManager? materialsManager,
    required Uint8List data,
    Map<String, String>? encryptionContext,
  }) async {
    final mm = _getMaterialsManager(keyring, materialsManager);

    final encryptionHandler = EncryptionHandler(
      mm,
      _encryptionAlgorithm,
      encryptionContext ?? {},
      _encryptionFrameSize,
    );

    await encryptionHandler.init();

    final result = await encryptionHandler.processFrames(BufferReader(data));

    return CryptoResult(
      result,
      encryptionContext ?? {},
      _encryptionAlgorithm,
    );
  }

  /// Encrypts the [stream] under the wrapping key(s).
  ///
  /// Supply either a [Keyring] or a customised [MaterialsManager].
  /// If a [Keyring] is supplied, the SDK uses the [DefaultMaterialsManager].
  ///
  /// Optionally, supply a set of non-secret key-value pairs in
  /// [encryptionContext] to be included in, and cryptographically bound to,
  /// the ciphertext.
  ///
  /// Returns the result as a [StreamingCryptoResult]. Listen to the stream
  /// returned in [result.stream] to receive the ciphertext.
  Future<StreamingCryptoResult> encryptStream({
    Keyring? keyring,
    MaterialsManager? materialsManager,
    required Stream<List<int>> stream,
    Map<String, String>? encryptionContext,
  }) async {
    final mm = _getMaterialsManager(keyring, materialsManager);

    final encryptionHandler = EncryptionHandler(
      mm,
      _encryptionAlgorithm,
      encryptionContext ?? {},
      _encryptionFrameSize,
    );

    await encryptionHandler.init();

    return StreamingCryptoResult(
      encryptionHandler.processStream(StreamReader(stream)),
      encryptionContext ?? {},
      _encryptionAlgorithm,
    );
  }

  /// Decrypts the [data] using any of the available wrapping keys.
  ///
  /// Supply either a [Keyring] or a customised [MaterialsManager].
  /// If a [Keyring] is supplied, the SDK uses the [DefaultMaterialsManager].
  ///
  /// Returns the result as a [CryptoResult].
  ///
  /// Throws an exception if the [data] cannot be decrypted.
  Future<CryptoResult> decryptData({
    Keyring? keyring,
    MaterialsManager? materialsManager,
    required Uint8List data,
  }) async {
    final mm = _getMaterialsManager(keyring, materialsManager);

    final reader = HashingReader(BufferReader(data));

    final headers = CiphertextHeaders();
    await headers.deserialize(reader);

    final decryptionHandler = DecryptionHandler(
      mm,
      headers,
      _maxEncryptedDataKeys,
    );

    await decryptionHandler.init();

    final result = await decryptionHandler.processFrames(reader);

    if (reader.available > 0) {
      throw AwsCryptoException('ciphertext has trailing garbage');
    }

    // if we get here the signature (if present) was verified

    return CryptoResult(
      result,
      decryptionHandler.encryptionContext,
      headers.cryptoAlgorithm,
    );
  }

  /// Decrypts the [stream] using any of the available wrapping keys.
  ///
  /// Supply either a [Keyring] or a customised [MaterialsManager].
  /// If a [Keyring] is supplied, the SDK uses the [DefaultMaterialsManager].
  ///
  /// The structure of the ciphertext means that the digital signature (if
  /// present) is at the end. It cannot be verified until the whole ciphertext
  /// has been processed, and unverified plaintext sent to the result stream.
  /// NOTE: do not accept the validity of the plaintext stream until [onDone]
  /// is called.
  ///
  /// If you prefer to disallow signed ciphertexts, set
  /// [forbidSignedCiphertext].
  ///
  /// Returns the result as a [StreamingCryptoResult]. Listen to the stream
  /// returned in [result.stream] to receive the decrypted plaintext.
  ///
  /// Throws an exception if there is a problem with the headers of the
  /// ciphertext. If a problem is found in the body of the ciphertext, the
  /// output stream will call the stream's [onError].
  Future<StreamingCryptoResult> decryptStream({
    Keyring? keyring,
    MaterialsManager? materialsManager,
    required Stream<List<int>> stream,
    bool forbidSignedCiphertext = false,
  }) async {
    final mm = _getMaterialsManager(keyring, materialsManager);

    final reader = HashingReader(StreamReader(stream));

    final headers = CiphertextHeaders();
    await headers.deserialize(reader);

    if (forbidSignedCiphertext &&
        headers.cryptoAlgorithm.trailingSignatureLength > 0) {
      throw AwsCryptoException(
        'Ciphertext is signed, but not allowed',
      );
    }

    final decryptionHandler = DecryptionHandler(
      mm,
      headers,
      _maxEncryptedDataKeys,
    );

    await decryptionHandler.init();

    return StreamingCryptoResult(
      decryptionHandler.processStream(reader),
      decryptionHandler.encryptionContext,
      headers.cryptoAlgorithm,
    );
  }

  MaterialsManager _getMaterialsManager(
    Keyring? keyring,
    MaterialsManager? materialsManager,
  ) {
    if (keyring == null && materialsManager == null) {
      throw AwsCryptoException('Must supply a keyring or materials manager');
    }

    if (keyring != null && materialsManager != null) {
      throw AwsCryptoException('Must supply either a keyring or cmm, not both');
    }

    return materialsManager ?? DefaultMaterialsManager(keyring!);
  }
}
