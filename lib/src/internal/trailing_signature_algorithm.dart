import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/digests/sha384.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/curves/secp384r1.dart';
import 'package:pointycastle/key_generators/api.dart';
import 'package:pointycastle/key_generators/ec_key_generator.dart';
import 'package:pointycastle/signers/ecdsa_signer.dart';

import '../crypto_algorithm.dart';
import '../exception/exceptions.dart';
import '../util/random.dart';

abstract class TrailingSignatureAlgorithm {
  factory TrailingSignatureAlgorithm.fromAlgorithm(CryptoAlgorithm algorithm) {
    switch (algorithm) {
      case CryptoAlgorithm.algAes256GcmHkdfSha512CommitKeyEcdsaP384:
        return _EcdsaSignatureAlgorithm._(ECCurve_secp384r1());

      default:
        throw ArgumentError('Algorithm does not support trailing signature');
    }
  }

  /*static Digest digestForAlgorithm(CryptoAlgorithm algorithm) {
    switch (algorithm) {
      case CryptoAlgorithm.algAes256GcmHkdfSha512CommitKeyEcdsaP384:
        return SHA384Digest();

      default:
        throw ArgumentError('Algorithm does not support trailing signature');
    }
  }*/

  TrailingSignatureAlgorithm._();

  void deserializePublicKey(String keyString);

  String serializePublicKey();

  void updateHash(Uint8List b);

  Uint8List sign();

  bool verify(Uint8List signature);

  void generateKey();
}

class _EcdsaSignatureAlgorithm extends TrailingSignatureAlgorithm {
  _EcdsaSignatureAlgorithm._(this._domainParameters) : super._();

  final ECDomainParameters _domainParameters;

  ECPublicKey? _publicKey;
  ECPrivateKey? _privateKey;

  final _digest = SHA384Digest();

  @override
  void deserializePublicKey(String keyString) {
    final point = _domainParameters.curve.decodePoint(
      base64.decode(keyString),
    );

    if (point == null) {
      throw ArgumentError('unable to deserialize trailing signature key');
    }

    _publicKey = ECPublicKey(point, _domainParameters);
  }

  @override
  String serializePublicKey() {
    if (_publicKey == null) {
      throw StateError('no public key available');
    }
    return base64.encode(_publicKey!.Q!.getEncoded(true));
  }

  @override
  void updateHash(Uint8List b) {
    _digest.update(b, 0, b.length);
  }

  @override
  void generateKey() {
    final generator = ECKeyGenerator()
      ..init(ParametersWithRandom(
        ECKeyGeneratorParameters(_domainParameters),
        fortunaPrng,
      ));

    final keyPair = generator.generateKeyPair();
    _publicKey = keyPair.publicKey as ECPublicKey;
    _privateKey = keyPair.privateKey as ECPrivateKey;
  }

  @override
  Uint8List sign() {
    final signer = ECDSASigner()
      ..init(
        true,
        ParametersWithRandom(
          PrivateKeyParameter(_privateKey!),
          fortunaPrng,
        ),
      );

    final hash = Uint8List(_digest.digestSize);
    _digest.doFinal(hash, 0);
    final ecSignature = signer.generateSignature(hash) as ECSignature;

    return ASN1Sequence(elements: [
      ASN1Integer(ecSignature.r),
      ASN1Integer(ecSignature.s),
    ]).encode();
  }

  @override
  bool verify(Uint8List signature) {
    if (signature.length < 100 || signature[0] != 0x30) {
      throw BadCiphertextException('invalid signature');
    }

    final seqLen = signature[1];
    if (signature.length != seqLen + 2) {
      throw BadCiphertextException('invalid signature');
    }

    final rs = signature.sublist(2, signature.length);
    if (rs[0] != 2) {
      throw BadCiphertextException('invalid signature');
    }

    final rLength = rs[1];
    if (rLength < 1 || rLength + 2 > rs.length) {
      throw BadCiphertextException('invalid signature');
    }

    final r = rs.sublist(2, 2 + rLength);
    final ss = rs.sublist(2 + rLength);
    if (ss.length < 2 || ss[0] != 2) {
      throw BadCiphertextException('invalid signature');
    }

    final sLength = ss[1];
    if (sLength < 1 || ss.length != sLength + 2) {
      throw BadCiphertextException('invalid signature');
    }

    final s = ss.sublist(2, sLength + 2);
    final ecSignature = ECSignature(_decodeBigInt(r), _decodeBigInt(s));

    final signer = ECDSASigner()..init(false, PublicKeyParameter(_publicKey!));
    final hash = Uint8List(_digest.digestSize);
    _digest.doFinal(hash, 0);
    return signer.verifySignature(hash, ecSignature);
  }

  BigInt _decodeBigInt(List<int> bytes) {
    var negative = bytes.isNotEmpty && bytes[0] & 0x80 == 0x80;

    BigInt result;

    if (bytes.length == 1) {
      result = BigInt.from(bytes[0]);
    } else {
      result = BigInt.zero;
      for (var i = 0; i < bytes.length; i++) {
        var item = bytes[bytes.length - i - 1];
        result |= (BigInt.from(item) << (8 * i));
      }
    }
    return result != BigInt.zero
        ? negative
            ? result.toSigned(result.bitLength)
            : result
        : BigInt.zero;
  }
}
