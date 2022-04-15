import 'dart:typed_data';

import 'crypto_algorithm.dart';

/// A holder for the result of an [AwsCrypto.encryptData()] or
/// [AwsCrypto.decryptData()]
class CryptoResult {
  CryptoResult(this.result, this.encryptionContext, this.cryptoAlgorithm);

  /// The plaintext or ciphertext, depending on the direction
  Uint8List result;

  /// The encryption context passed in, or extracted from the ciphertext
  Map<String, String> encryptionContext;

  /// The algorithm used in encryption/decryption.
  CryptoAlgorithm cryptoAlgorithm;
}

/// A holder for the result of an [AwsCrypto.encryptStream()] or
/// [AwsCrypto.decryptStream()]
class StreamingCryptoResult {
  StreamingCryptoResult(
    this.stream,
    this.encryptionContext,
    this.cryptoAlgorithm,
  );

  /// The [Stream<Uint8List>] of the ciphertext (for encrypt)
  /// or plaintext (for decrypt).
  ///
  /// [Stream.listen()] to the stream to process the data.
  ///
  /// On decryption,
  /// the stream triggers [onError] if an error is encountered in the
  /// ciphertext. Note that the signature (if present) is only verified
  /// at the end of the ciphertext. If [onError] is triggered, any
  /// previously processed plaintext *must* be discarded.
  Stream<Uint8List> stream;

  /// The encryption context passed in, or extracted from the ciphertext
  Map<String, String> encryptionContext;

  /// The algorithm used in encryption/decryption.
  CryptoAlgorithm cryptoAlgorithm;
}
