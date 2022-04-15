import 'package:pointycastle/api.dart';
import 'package:pointycastle/digests/sha1.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/sha384.dart';
import 'package:pointycastle/digests/sha512.dart';

/// The supported cipher suites used to wrap (encrypt) the data key.
///
/// The wrapping algorithms starting 'aes' are used with AES wrapping/master
/// keys. The wrapping algorithm must match the size of the key.
///
/// The wrapping algorithms starting 'rsa' are used with asymmetrical RSA
/// wrapping/master keys.
enum WrappingAlgorithm {
  /// Wraps the data key under a 128 bit AES wrapping key
  aes128GcmIv12Tag16NoPadding,

  /// Wraps the data key under a 192 bit AES wrapping key
  aes192GcmIv12Tag16NoPadding,

  /// Wraps the data key under a 256 bit AES wrapping key
  aes256GcmIv12Tag16NoPadding,

  /// Wraps the data key under an RSA keypair using PKCS1 padding
  rsaPkcs1,

  /// Wraps the data key under an RSA keypair using OAEP padding with MGF1 and
  /// an SHA-1 hash
  rsaOaepSha1Mgf1,

  /// Wraps the data key under an RSA keypair using OAEP padding with MGF1 and
  /// an SHA-256 hash
  rsaOaepSha256Mgf1,

  /// Wraps the data key under an RSA keypair using OAEP padding with MGF1 and
  /// an SHA-384 hash
  rsaOaepSha384Mgf1,

  /// Wraps the data key under an RSA keypair using OAEP padding with MGF1 and
  /// an SHA-512 hash
  rsaOaepSha512Mgf1,
}

extension WrappingAlgorithmUtils on WrappingAlgorithm {
  Digest get digest {
    switch (this) {
      case WrappingAlgorithm.rsaOaepSha1Mgf1:
        return SHA1Digest();
      case WrappingAlgorithm.rsaOaepSha256Mgf1:
        return SHA256Digest();
      case WrappingAlgorithm.rsaOaepSha384Mgf1:
        return SHA384Digest();
      case WrappingAlgorithm.rsaOaepSha512Mgf1:
        return SHA512Digest();
      default:
        throw ArgumentError('$this does not use a digest');
    }
  }

  int get keySizeBytes {
    switch (this) {
      case WrappingAlgorithm.aes128GcmIv12Tag16NoPadding:
        return 128 ~/ 8;
      case WrappingAlgorithm.aes192GcmIv12Tag16NoPadding:
        return 192 ~/ 8;
      case WrappingAlgorithm.aes256GcmIv12Tag16NoPadding:
        return 256 ~/ 8;
      default:
        throw ArgumentError('$this does not use an AES key');
    }
  }
}
