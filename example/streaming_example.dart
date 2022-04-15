import 'dart:convert';
import 'dart:typed_data';

import 'package:aws_encryption_sdk/aws_encryption_sdk.dart';
import 'package:aws_encryption_sdk/src/util/random.dart';
import 'package:pointycastle/export.dart';

/// This sample encrypts and decrypts a stream of bytes
/// using an AES 256 bit key.
///
/// It uses the default algorithm, and supplies (and checks) a context.
void main() async {
  // Instantiate an instance of the library, with the defaults
  final awsCrypto = AwsCrypto();

  // The AES wrapping key can be 128, 192 or 256 bits
  final key = base64.decode('AAECAwQFBgcAAQIDBAUGBwABAgMEBQYHAAECAwQFBgc=');
  assert(key.length * 8 == 256);

  // Instantiate a keyring, giving the key a name in a namespace.
  // Do not include anything secret in the name or namespace as they will
  // be visible in the ciphertext. You must supply the same values to the
  // decryption keyring.
  //
  // Choose the correct wrapping algorithm based on the size of the key.
  final keyring = RawAesKeyring(
    'examples',
    'aes-256-example',
    key,
    WrappingAlgorithm.aes256GcmIv12Tag16NoPadding,
  );

  // The encryption context consists of key, value pairs that are
  // cryptographically bound to the ciphertext. Do not include secret data
  // in the context as it is visible in the ciphertext.
  final encryptionContext = {
    'example key': 'example value',
    'another key': 'and another value',
  };

  // encrypt the stream with the keyring and bind the context
  final encryptionResult = await awsCrypto.encryptStream(
    stream: _generateRandomStream(),
    keyring: keyring,
    encryptionContext: encryptionContext,
  );

  // decrypt the resulting ciphertext, which is another stream
  final decryptionResult = await awsCrypto.decryptStream(
    stream: encryptionResult.stream,
    keyring: keyring,
  );

  // decryption provides the original context, so we can...
  final decryptedContext = decryptionResult.encryptionContext;
  print(decryptedContext);

  // ... check that we get back what we supplied originally
  assert(decryptedContext.length == encryptionContext.length);
  for (final k in decryptedContext.keys) {
    assert(decryptedContext[k] == encryptionContext[k]);
  }

  // calculate the hash of the decrypted plaintext to compare with the
  // hash of the original plaintext as randomly generated in
  // _generateRandomStream()
  final digest = SHA256Digest();
  await for (final b in decryptionResult.stream) {
    digest.update(b, 0, b.length);
  }
  final hash = Uint8List(digest.digestSize);
  digest.doFinal(hash, 0);
  print('decrypted plaintext hash is ${base64.encode(hash)}');
}

Stream<Uint8List> _generateRandomStream() async* {
  final data = List.generate(10, (_) => makeRandom(1000));
  final digest = SHA256Digest();
  for (final b in data) {
    digest.update(b, 0, b.length);
  }
  final hash = Uint8List(digest.digestSize);
  digest.doFinal(hash, 0);
  print('original  plaintext hash is ${base64.encode(hash)}');

  for (final b in data) {
    await Future.delayed(Duration(milliseconds: 50));
    yield b;
  }
}
