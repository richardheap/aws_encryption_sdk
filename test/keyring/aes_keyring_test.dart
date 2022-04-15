import 'dart:convert';
import 'dart:typed_data';

import 'package:aws_encryption_sdk/aws_encryption_sdk.dart';
import 'package:aws_encryption_sdk/src/material/cryptographic_material.dart';
import 'package:test/test.dart';

void main() {


  final matAes128 = base64.decode('AAECAwQFBgcICRAREhMUFQ==');
  final matAes192 = base64.decode('AAECAwQFBgcICRAREhMUFRYXGBkgISIj');
  final matAes256 =
      base64.decode('AAECAwQFBgcICRAREhMUFRYXGBkgISIjJCUmJygpMDE=');

  group('AES keyring tests', () {
    late RawAesKeyring keyring;

    setUp(() {
      keyring = RawAesKeyring(
        'ns',
        'n',
        matAes256,
        WrappingAlgorithm.aes256GcmIv12Tag16NoPadding,
      );
    });

    test('can encrypt and decrypt', () {
      final algorithm = CryptoAlgorithm.algAes256GcmHkdfSha512CommitKey;
      final encryptionContext = {'key': 'value'};
      final encryptionMaterials = EncryptionMaterials(
        algorithm,
        encryptionContext,
        null,
      );
      keyring.onEncrypt(encryptionMaterials);
      expect(encryptionMaterials.plaintextDataKey, isNotNull);
      expect(
        (encryptionMaterials.plaintextDataKey ?? Uint8List(0)).length,
        algorithm.dataKeyLength,
      );
      expect(encryptionMaterials.encryptedDataKeys.length, 1);

      final dataKey = keyring.onDecrypt(
        algorithm,
        encryptionMaterials.encryptedDataKeys,
        encryptionContext,
      );
      expect(dataKey, encryptionMaterials.plaintextDataKey);
    });

    test('detects reserved name', () {
      expect(
          () => RawAesKeyring(
                'aws-kms',
                'test',
                matAes128,
                WrappingAlgorithm.aes128GcmIv12Tag16NoPadding,
              ),
          throwsArgumentError);
    });
  });

  group('AES keyring wrapping tests', () {
    test('detects bad wrapper', () {
      expect(
        () => RawAesKeyring(
          'namespace',
          'name',
          matAes128,
          WrappingAlgorithm.aes192GcmIv12Tag16NoPadding,
        ),
        throwsArgumentError,
      );
      expect(
        () => RawAesKeyring(
          'namespace',
          'name',
          matAes192,
          WrappingAlgorithm.aes256GcmIv12Tag16NoPadding,
        ),
        throwsArgumentError,
      );
      expect(
        () => RawAesKeyring(
          'namespace',
          'name',
          Uint8List(8),
          WrappingAlgorithm.aes128GcmIv12Tag16NoPadding,
        ),
        throwsArgumentError,
      );
      expect(
        () => RawAesKeyring(
          'namespace',
          'name',
          matAes128,
          WrappingAlgorithm.rsaPkcs1,
        ),
        throwsArgumentError,
      );
      expect(
        () => RawAesKeyring(
          'namespace',
          'name',
          matAes128,
          WrappingAlgorithm.rsaOaepSha256Mgf1,
        ),
        throwsArgumentError,
      );
    });
  });
}
