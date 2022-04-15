import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/block/aes.dart';
import 'package:pointycastle/block/modes/gcm.dart';

import '../exception/exceptions.dart';
import 'sodium.dart';

enum SodiumPolicy {
  useSodiumIfPresent,
  requireSodium,
  neverUseSodium,
}

LibSodium? _libSodium;
var _triedSodium = false;

bool _gotSodium(SodiumPolicy sodiumPolicy) {
  if (sodiumPolicy == SodiumPolicy.neverUseSodium) {
    return false;
  }

  if (_libSodium != null) {
    return true;
  }

  if (_triedSodium) {
    return false;
  }

  _triedSodium = true;

  try {
    _libSodium = LibSodium();
  } catch (e) {
    print(e);
  }

  if (_libSodium == null && sodiumPolicy == SodiumPolicy.requireSodium) {
    throw UnsupportedError(
      'policy requires libSodium, but it is not available',
    );
  }

  return _libSodium != null;
}

Uint8List encrypt(
  Uint8List key,
  Uint8List nonce,
  Uint8List associatedData,
  Uint8List plaintext, [
  SodiumPolicy sodiumPolicy = SodiumPolicy.useSodiumIfPresent,
]) {
  if (_gotSodium(sodiumPolicy) && key.length == 32) {
    return _libSodium!.encrypt(key, nonce, associatedData, plaintext);
  }
  return _getCipher(
    key,
    nonce,
    associatedData,
    true,
  ).process(plaintext);
}

Uint8List decrypt(
  Uint8List key,
  Uint8List nonce,
  Uint8List associatedData,
  Uint8List ciphertext, [
  SodiumPolicy sodiumPolicy = SodiumPolicy.useSodiumIfPresent,
]) {
  if (_gotSodium(sodiumPolicy) && key.length == 32) {
    try {
      return _libSodium!.decrypt(key, nonce, associatedData, ciphertext);
    } on ArgumentError {
      throw BadCiphertextException('GCM decrypt failed');
    }
  }
  try {
    return _getCipher(
      key,
      nonce,
      associatedData,
      false,
    ).process(ciphertext);
  } on InvalidCipherTextException {
    throw BadCiphertextException('GCM decrypt failed');
  }
}

GCMBlockCipher _getCipher(
  Uint8List key,
  Uint8List nonce,
  Uint8List associatedData,
  bool forEncryption,
) =>
    GCMBlockCipher(AESEngine())
      ..init(
        forEncryption,
        AEADParameters(KeyParameter(key), 16 * 8, nonce, associatedData),
      );
