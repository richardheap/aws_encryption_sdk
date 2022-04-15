import 'dart:convert';
import 'dart:typed_data';

import 'package:aws_encryption_sdk/aws_encryption_sdk.dart';

/// This sample encrypts and decrypts a string using an AES 256 bit key.
///
/// It uses the default algorithm, and supplies (and checks) a context.
void main() async {
  // the secret message
  final hello = 'Hello World';

  // converted to bytes
  final data = utf8.encode(hello) as Uint8List;

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

  // encrypt the data with the keyring and bind the context
  final encryptionResult = await awsCrypto.encryptData(
    data: data,
    keyring: keyring,
    encryptionContext: encryptionContext,
  );

  final cipherText = encryptionResult.result;
  print('the length of the ciphertext is ${cipherText.length} bytes');

  // decrypt the ciphertext
  final decryptionResult = await awsCrypto.decryptData(
    data: cipherText,
    keyring: keyring,
  );

  final decryptedData = utf8.decode(decryptionResult.result);
  assert(decryptedData == hello);
  print(decryptedData);

  // decryption provides the original context, so we can...
  final decryptedContext = decryptionResult.encryptionContext;
  print(decryptedContext);

  // ... check that we get back what we supplied originally
  assert(decryptedContext.length == encryptionContext.length);
  for (final k in decryptedContext.keys) {
    assert(decryptedContext[k] == encryptionContext[k]);
  }
}
