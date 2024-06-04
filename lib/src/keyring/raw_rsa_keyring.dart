import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/asymmetric/api.dart';
import 'package:pointycastle/asymmetric/oaep.dart';
import 'package:pointycastle/asymmetric/pkcs1.dart';
import 'package:pointycastle/asymmetric/rsa.dart';

import '../crypto_algorithm.dart';
import '../encrypted_data_key.dart';
import '../exception/exceptions.dart';
import '../material/cryptographic_material.dart';
import '../model/key_blob.dart';
import '../util/random.dart';
import '../wrapping_algorithm.dart';
import 'keyring.dart';

/// A [Keyring] that provides one half of an RSA key pair. The public key
/// is used during encryption; the private key is used during decryption.
///
/// RSA keys are often used as emergency keys in a multi key ring.
/// The public part is used to
/// encrypt. The private part is kept safe and is only ever needed for
/// decryption if the other keys in the original multi keyring are lost.
class RawRsaKeyring extends Keyring {
  /// Constructs a [Keyring] for a asymmetrical RSA wrapping key.
  ///
  /// [namespace] is a non-secret name to describe the group of keys, and
  /// must not be a reserved work (e.g. aws-kms) and [name] is this particular
  /// key's non-secret name.
  ///
  /// [wrappingKey] is an [RSAPublicKey], and is used during encryption.
  ///
  /// [unwrappingKey] is an [RSAPrivateKey], and is used during decryption.
  ///
  /// [wrappingAlgorithm] selects which algorithm is used to wrap (encrypt)
  /// the data key. It must be one of the [WrappingAlgorithm]s that start
  /// with "rsa".
  RawRsaKeyring(
    String namespace,
    String name,
    RSAPublicKey? wrappingKey,
    RSAPrivateKey? unwrappingKey,
    WrappingAlgorithm wrappingAlgorithm,
  )   : _wrappingKey = wrappingKey,
        _unwrappingKey = unwrappingKey,
        _wrappingAlgorithm = wrappingAlgorithm,
        super(namespace, name) {
    if (namespace == 'aws-kms') {
      throw ArgumentError('aws-kms is a reserved name');
    }
    if (!wrappingAlgorithm.name.startsWith('rsa')) {
      throw ArgumentError('wrapping algorithm incompatible with RSA key');
    }
  }

  final RSAPublicKey? _wrappingKey;
  final RSAPrivateKey? _unwrappingKey;
  final WrappingAlgorithm _wrappingAlgorithm;

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
        if (edk.providerId == namespace && edk.providerInfoString == name) {
          if (_unwrappingKey == null) {
            throw ArgumentError('this keyring has no unwrapping key');
          }

          return _cipher(false).process(edk.encryptedDataKey);
        }
      } catch (e) {
        sb.writeln(e.toString());
      }
    }
    throw CannotUnwrapDataKeyException(sb.toString());
  }

  @override
  FutureOr<void> onEncrypt(EncryptionMaterials materials) {
    if (_wrappingKey == null) {
      return null;
    }

    materials.plaintextDataKey ??=
        makeRandom(materials.algorithm.dataKeyLength);

    if (materials.plaintextDataKey != null) {
      if (_wrappingKey == null) {
        throw ArgumentError('this keyring has no wrapping key');
      }

      final ek = _cipher(true).process(materials.plaintextDataKey!);

      materials.encryptedDataKeys.add(KeyBlob(
        utf8.encode(namespace),
        utf8.encode(name),
        ek,
      ));
    }
  }

  AsymmetricBlockCipher _cipher(bool encrypt) {
    final keyParameter = encrypt
        ? PublicKeyParameter<RSAPublicKey>(_wrappingKey!)
        : PrivateKeyParameter<RSAPrivateKey>(_unwrappingKey!);
    return _underlyingCipher()..init(encrypt, keyParameter);
  }

  AsymmetricBlockCipher _underlyingCipher() {
    switch (_wrappingAlgorithm) {
      case WrappingAlgorithm.rsaPkcs1:
        return PKCS1Encoding(RSAEngine());

      case WrappingAlgorithm.rsaOaepSha1Mgf1:
      case WrappingAlgorithm.rsaOaepSha256Mgf1:
      case WrappingAlgorithm.rsaOaepSha384Mgf1:
      case WrappingAlgorithm.rsaOaepSha512Mgf1:
        return OAEPEncoding.withCustomDigest(
          () => _wrappingAlgorithm.digest,
          RSAEngine(),
        );
      default:
        throw UnimplementedError('wrapping algorithm is incompatible with key');
    }
  }
}
