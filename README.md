An implementation of the
[AWS Encryption SDK](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/introduction.html) in Dart.

## Overview
The AWS Encryption SDK website describes it as
"a client-side encryption library
designed to make it easy for everyone to encrypt and decrypt data
using industry standards and best practices". There are implementations
available in C, Java, Typescript and Python. This is a partial
implementation in Dart.

The SDK moved from v1 to v2 several years ago. This implementation only
supports v2 cipher suites and formats.

The SDK encrypts and decrypts data using wrapping keys. Each plaintext
is encrypted using a committed key derived from a randomly generated
(data) key.
The data key is encrypted in one or more wrapping keys.
The encrypted keys are stored in the ciphertext. To decrypt, the SDK
decrypts at least one of the encrypted keys to recover the data key
and from that the encryption key.

The SDK optionally digitally signs the ciphertext with ECDSA.

### Cipher Suites
The two supported cipher suites are the most modern ones defined by
the SDK standard. They are the same, except for the inclusion of
the digital signature or not.

| Encryption algorithm | Data key length (bits) | Key derivation algorithm | Signature algorithm | Key commitment algorithm |
| --- | --- | --- | --- | --- |
| AES-GCM | 256 | HKDF with SHA-512 | ECDSA with P-384 and SHA-384 | HKDF with SHA-512 |
| AES-GCM | 256 | HKDF with SHA-512 | None | HKDF with SHA-512 |

### Keyrings
Wrapping keys are provided by keyrings. This implementation supports:
- Symmetrical AES keys (128, 192 and 256 bits)
- Asymmetrical RSA keys (with PKCS1 and OAEP padding options)
- AWS KMS symmetrical keys

A 'multi' keyring supports encryption under more than one wrapping key,
and decryption by any of the supplied wrapping keys.

## Usage

A simple usage example:

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

### Streaming

If the plaintext and ciphertext fit into memory, use the `encryptData` and `decryptData` methods.
The SDK can also process streams.

Because of the `async` nature of the API (to allow for the KMS interface, which is itself `async`)
the streaming interface isn't made available as a `StreamTransformer` or `Codec`. See the
`streaming_example.dart` for usage.

### Options
To control the cipher suite for encryption (the only choice available at the moment
is whether to sign with ECDSA), specify the `encryptionAlgorithm` when constructing the
`AWSCrypto` instance. The other option available on the constructor is `encryptionFrameSize`
which sets the block size used on encryption, defaulting to 4096.

Set the wrapping algorithm for RSA keys when constructing the key ring, for example:

```dart
  final rsaKeyring = RawRsaKeyring(
    'examples',
    'rsa-4096-example',
    keyPair.publicKey,
    keyPair.privateKey,
    WrappingAlgorithm.rsaOaepSha256Mgf1,
  );
```

(Don't use PKCS1 except for backwards compatibility.
Also note that the `C` implementation only supports OAEP with SHA-256, so use this if `C`
compatibility is important.)

### Hardware Acceleration

By default, this implementation uses `pointycastle` for all cryptographic operations. The
main operation is the AES-256-GCM encryption/decryption of the actual plaintext/ciphertext.

Most processors now support hardware acceleration of the AES rounds and multiply operation
used in GCM. To access these, the implementation will look for a copy of the `libsodium`
shared library. If it finds it, and the processor supports the relevant instructions, all
AES-256-GCM operations are handled by FFI calls to libsodium. This can give up to 100 times
speed improvement.

It looks for the following files:

| Operating System | Filename |
| --- | --- |
| Windows | C:\Windows\System32\libsodium.dll |
| Linux | /usr/lib64/libsodium.so.23 |

### Examples

See the examples folder for additional examples.

The [developer guide](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/encryption-sdk-developer-guide.pdf)
is specific to other programming languages but may be helpful in understanding concepts.

## Interoperability
This implementation passes the decryption test vectors in the 2.3.0
suite for which it has support. It skips v1 format ciphertexts and AWS
KMS MRK keys. Ciphertexts created with this implementation have been
tested with the Java implementation.

## Limitations
The SDK defines two styles of framing: framed and unframed (deprecated).
This implementation can read both, but only creates framed.

AWS MRK keys are not implemented.

The caching material manager (CMM) is not implemented.

Using the algorithm with signing (`algAes256GcmHkdfSha512CommitKeyEcdsaP384`) *significantly*
reduces performance of both encryption and decryption. (About half of the extra time is spent
hashing the ciphertext and half performing the ECDSA calculations.) The initial plan was to
replace libsodium with libcrypto (which should have been able to do to speed up the GCM, SHA
and ECDSA parts), but it didn't have as good performance on the raw AES-GCM as libsodium.
While it is best practise to use signing, its use is optional:

> It's a best practice to use an algorithm suite with signing.
> Digital signatures verify the message sender
> was authorized to send the message and protect the integrity of the message.
> All versions of the AWS Encryption SDK use algorithm suites with signing by default.

> If your security requirements don't include digital signatures,
> you *can select an algorithm suite without digital signatures*.
> However, we recommend using digital signatures,
> especially when one group of users encrypts data
> and a different set of users decrypts that data.

TL;DR without signing an attacker with *decrypt-only* KMS rights can alter a ciphertext;
with signing they cannot.

When encrypting a plaintext with an exact number of frames, this implementation creates a
final zero length frame. The spec prefers that the previous frame be the final frame.
> When the length of the Plaintext is an exact multiple of the Frame Length
> (including if it is equal to the frame length), the Final Frame encrypted content length
> SHOULD be equal to the frame length but MAY be 0.
 
## Notice
This implementation relies heavily on the structure of the Java implementation, published by
Amazon [here][javaImpl] under the Apache license, and should be considered a derivative work thereof.
The Java implementation contains the follow Notice:
> Copyright 2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.


## Features and bugs

Please file feature requests and bugs at the [issue tracker][tracker].

[tracker]: http://example.com/issues/replaceme
[javaImpl]: https://github.com/aws/aws-encryption-sdk-java
