## Example Usage

- Instantiate an `AwsCrypto`
- Instatiate a keyring of the appropriate type
- Call `encryptData` and/or `decryptData` - the result is a `CryptoResult`

```dart
import 'package:aws_encryption_sdk/aws_encryption_sdk.dart';

main() async {
  // Instantiate an instance of the library, with the defaults
  final awsCrypto = AwsCrypto();

  // Instantiate a keyring, using an AWS KMS key id
  final keyring = AwsKmsKeyring(
    'arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f',
  );

  // encrypt the data with the keyring
  final encryptionResult = await awsCrypto.encryptData(
    data: data,
    keyring: keyring,
  );
}
```

## List of complete examples provided

- `example/aws_kms_example.dart` Uses an AWS KMS key to encrypt and decrypt
- `example/raw_aes_example.dart` Encrypts and decrypts under a 256-bit AES key
- `example/raw_multi_example.dart` Encrypts under both an RSA public key and AES key, then decrypts using each individually
- `example/streaming_example.dart` Demonstrates encryption/decryption of data using streams (useful when the data is too big to fit in memory)
