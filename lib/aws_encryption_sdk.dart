/// An implementation of the AWS Encryption SDK
///
/// This implementation supports most of the v2 features, but does not
/// implement any legacy/deprecated features.
///
/// It provides methods for encrypting and decrypting buffers and streams.
library aws_encryption_sdk;

export 'src/aws_encryption_sdk_impl.dart';
export 'src/crypto_algorithm.dart';
export 'src/crypto_result.dart';
export 'src/exception/exceptions.dart';
export 'src/keyring/aws_kms_keyring.dart';
export 'src/keyring/keyring.dart';
export 'src/keyring/multi_keyring.dart';
export 'src/keyring/raw_aes_keyring.dart';
export 'src/keyring/raw_rsa_keyring.dart';
export 'src/wrapping_algorithm.dart';
