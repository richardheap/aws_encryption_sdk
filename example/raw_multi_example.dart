import 'dart:convert';

import 'package:aws_encryption_sdk/aws_encryption_sdk.dart';
import 'package:aws_encryption_sdk/src/util/random.dart';
import 'package:pointycastle/export.dart';

/// This sample encrypts a string using an AES 256 bit key and an RSA public
/// key. Then it decrypts using just the AES key and just the RSA private key.
///
/// It uses the default algorithm, and supplies (and checks) a context.
void main() async {
  // the secret message
  final hello = 'Hello World';

  // converted to bytes
  final data = utf8.encode(hello);

  // Instantiate an instance of the library, with the defaults
  final awsCrypto = AwsCrypto();

  // The AES wrapping key can be 128, 192 or 256 bits
  final key = base64.decode('AAECAwQFBgcAAQIDBAUGBwABAgMEBQYHAAECAwQFBgc=');
  assert(key.length * 8 == 256);

  final keyPair = generateRSAKeyPair(bitLength: 4096);

  // Instantiate an AES keyring, giving the key a name in a namespace.
  // Do not include anything secret in the name or namespace as they will
  // be visible in the ciphertext. You must supply the same values to the
  // decryption keyring.
  //
  // Choose the correct wrapping algorithm based on the size of the key.
  final aesKeyring = RawAesKeyring(
    'examples',
    'aes-256-example',
    key,
    WrappingAlgorithm.aes256GcmIv12Tag16NoPadding,
  );

  // Instantiate an RSA keyring.
  // Choose a valid wrapping algorithm.
  // (Don't use PKCS1 except for backwards compatibility.)
  final rsaKeyring = RawRsaKeyring(
    'examples',
    'rsa-2048-example',
    keyPair.publicKey,
    keyPair.privateKey,
    WrappingAlgorithm.rsaOaepSha256Mgf1,
  );

  final encryptKeyring = MultiKeyring(
    generatorKeyring: aesKeyring,
    childKeyrings: [rsaKeyring],
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
    keyring: encryptKeyring,
    encryptionContext: encryptionContext,
  );

  final cipherText = encryptionResult.result;
  print('the length of the ciphertext is ${cipherText.length} bytes');

  // decrypt the ciphertext using just the AES keyring
  final decryptionResult = await awsCrypto.decryptData(
    data: cipherText,
    keyring: aesKeyring,
  );

  final decryptedData = utf8.decode(decryptionResult.result);
  assert(decryptedData == hello);
  print(decryptedData);

  // decryption provides the original context, so we can...
  final decryptedContext = decryptionResult.encryptionContext;

  // ... check that we get back what we supplied originally
  assert(decryptedContext.length == encryptionContext.length);
  for (final k in decryptedContext.keys) {
    assert(decryptedContext[k] == encryptionContext[k]);
  }

  // and prove that just the RSA keyring can decrypt it too
  final result2 = await awsCrypto.decryptData(
    data: cipherText,
    keyring: rsaKeyring,
  );
  assert(utf8.decode(result2.result) == hello);
}

AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> generateRSAKeyPair({
  int bitLength = 2048,
}) {
  // Create an RSA key generator and initialize it
  final keyGen = RSAKeyGenerator()
    ..init(ParametersWithRandom(
      RSAKeyGeneratorParameters(BigInt.from(65537), bitLength, 64),
      fortunaPrng,
    ));

  final pair = keyGen.generateKeyPair();

  return AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>(
    pair.publicKey as RSAPublicKey,
    pair.privateKey as RSAPrivateKey,
  );
}
