import 'dart:typed_data';

import 'exception/exceptions.dart';
import 'internal/committed_key.dart';
import 'model/ciphertext_headers.dart';
import 'util/uint8list_compare.dart';

/// Enumeration of implemented cipher-suite algorithms
enum CryptoAlgorithm {
  /// AES-256 GCM with HKDF derived and committed key
  algAes256GcmHkdfSha512CommitKey,

  /// AES-256 GCM with HKDF derived and committed key, with ECDSA signature
  algAes256GcmHkdfSha512CommitKeyEcdsaP384,
}

const int _gcmMaxContentLength = (1 << 36) - 32;

final _cryptoAlgorithms = {
  CryptoAlgorithm.algAes256GcmHkdfSha512CommitKey: _CryptoAlgorithmDetails(
    CryptoAlgorithm.algAes256GcmHkdfSha512CommitKey,
    2,
    128,
    12,
    16,
    _gcmMaxContentLength,
    'AES',
    32,
    0x0478,
    'SHA-512/HKDF',
    32,
    true,
    null,
    0,
    'SHA-512/HKDF',
    32,
    32,
    32,
  ),
  CryptoAlgorithm.algAes256GcmHkdfSha512CommitKeyEcdsaP384:
      _CryptoAlgorithmDetails(
    CryptoAlgorithm.algAes256GcmHkdfSha512CommitKeyEcdsaP384,
    2,
    128,
    12,
    16,
    _gcmMaxContentLength,
    'AES',
    32,
    0x0578,
    'SHA-512/HKDF',
    32,
    true,
    'SHA384withECDSA',
    103,
    'SHA-512/HKDF',
    32,
    32,
    32,
  ),
};

extension CryptoAlgorithmUtils on CryptoAlgorithm {
  static CryptoAlgorithm byValue(int version, int value) {
    return _cryptoAlgorithms.values
        .firstWhere(
          (d) => d.value == value && d.messageFormatVersion == version,
        )
        ._cryptoAlgorithm;
  }

  _CryptoAlgorithmDetails get _details => _cryptoAlgorithms[this]!;

  int get messageFormatVersion => _details.messageFormatVersion;

  int get messageIdLength => messageFormatVersion == 2 ? 32 : 16;

  int get nonceLengthBytes => _details.nonceLengthBytes;

  int get tagLengthBytes => _details.tagLengthBytes;

  int get value => _details.value;

  int get dataKeyLength => _details.dataKeyLength;

  String? get keyCommitmentAlgo => _details.keyCommitmentAlgo;

  bool get isCommitting => keyCommitmentAlgo != null;

  int get commitmentLength => _details.commitmentLength;

  int get commitmentNonceLength => _details.commitmentNonceLength;

  int get suiteDataLength => _details.suiteDataLength;

  int get trailingSignatureLength => _details.trailingSignatureLength;

  Uint8List? get nonce =>
      messageFormatVersion == 2 ? Uint8List(_details.nonceLengthBytes) : null;

  Uint8List getEncryptionKeyFromDataKey(
    final Uint8List dataKey,
    final CiphertextHeaders headers,
  ) {
    if (messageFormatVersion != 2) {
      throw UnimplementedError(
        'Support for message format version 1 not yet built.',
      );
    }

    // since we only support v2, all keys are committed
    return getCommittedEncryptionKey(dataKey, headers);
  }

  Uint8List getCommittedEncryptionKey(
    final Uint8List dataKey,
    final CiphertextHeaders headers,
  ) {
    final ck = CommittedKey.generate(this, dataKey, headers.messageId);
    if (!unsignedByteListEquals(ck.commitment, headers.suiteData)) {
      throw BadCiphertextException(
        'Key commitment validation failed. Key identity does not match the '
        'identity asserted in the message. Halting processing of this message.',
      );
    }

    return ck.ek;
  }
}

class _CryptoAlgorithmDetails {
  _CryptoAlgorithmDetails(
      this._cryptoAlgorithm,
      this.messageFormatVersion,
      this.blockSizeBits,
      this.nonceLengthBytes,
      this.tagLengthBytes,
      this.maxContentLength,
      this.keyAlgo,
      this.keyLengthBytes,
      this.value,
      this.dataKeyAlgo,
      this.dataKeyLength,
      this.safeToCache,
      this.trailingSignatureAlgo,
      this.trailingSignatureLength,
      this.keyCommitmentAlgo,
      this.commitmentLength,
      this.commitmentNonceLength,
      this.suiteDataLength);

  final CryptoAlgorithm _cryptoAlgorithm;
  int messageFormatVersion;
  int blockSizeBits;
  int nonceLengthBytes;
  int tagLengthBytes;
  int maxContentLength;
  String keyAlgo;
  int keyLengthBytes;
  int value;
  String dataKeyAlgo;
  int dataKeyLength;
  bool safeToCache;
  String? trailingSignatureAlgo;
  int trailingSignatureLength;
  String keyCommitmentAlgo;
  int commitmentLength;
  int commitmentNonceLength;
  int suiteDataLength;
}
