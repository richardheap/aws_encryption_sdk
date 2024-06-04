import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/key_derivators/api.dart';
import 'package:pointycastle/key_derivators/hkdf.dart';

import '../crypto_algorithm.dart';

class CommittedKey {
  CommittedKey._(this._ek, this._commitment);

  factory CommittedKey.generate(
    CryptoAlgorithm algo,
    Uint8List dataKey,
    Uint8List nonce,
  ) {
    if (!algo.isCommitting) {
      throw StateError('uncommitted key error');
    }

    if (nonce.length != algo.commitmentNonceLength) {
      throw StateError('commitment nonce length error');
    }

    if (dataKey.length != algo.dataKeyLength) {
      throw StateError('committed key data key length error');
    }

    if (algo.keyCommitmentAlgo! != 'SHA-512/HKDF') {
      throw UnimplementedError('unimplemented key commitment algorithm');
    }

    final commitmentLength = algo.commitmentLength;
    final commitment = Uint8List(commitmentLength);

    HKDFKeyDerivator(SHA512Digest())
      ..init(HkdfParameters(dataKey, commitmentLength, nonce))
      ..deriveKey(_commitLabel, 0, commitment, 0);

    final deriveKeyLabel = utf8.encode('__DERIVEKEY');
    final algId = algo.value;
    deriveKeyLabel[0] = (algId >> 8) & 0xff;
    deriveKeyLabel[1] = algId & 0xff;

    var dataKeyLength = algo.dataKeyLength;
    final ek = Uint8List(dataKeyLength);
    // NB don't reuse the key derivator - it has state - make a new one!!
    HKDFKeyDerivator(SHA512Digest())
      ..init(HkdfParameters(dataKey, dataKeyLength, nonce))
      ..deriveKey(deriveKeyLabel, 0, ek, 0);

    return CommittedKey._(ek, commitment);
  }

  Uint8List get ek => _ek;

  Uint8List get commitment => _commitment;

  static final _commitLabel = utf8.encode('COMMITKEY');

  final Uint8List _ek;
  final Uint8List _commitment;
}
