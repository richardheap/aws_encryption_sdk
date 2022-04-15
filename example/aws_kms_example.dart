import 'dart:convert';
import 'dart:typed_data';

import 'package:aws_encryption_sdk/aws_encryption_sdk.dart';

/// This sample encrypts and decrypts a string using an AWS KMS key.
///
/// It uses the default algorithm, and supplies (and checks) a context.
void main() async {
  // the secret message
  final hello = 'Hello World';

  // converted to bytes
  final data = utf8.encode(hello) as Uint8List;

  // Instantiate an instance of the library, with the defaults
  final awsCrypto = AwsCrypto();

  // Instantiate an AWS KMS keyring, supplying the ARN of the key.
  final keyring = AwsKmsKeyring(
    'arn:aws:kms:us-west-2:658956600833:'
    'key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f',
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
