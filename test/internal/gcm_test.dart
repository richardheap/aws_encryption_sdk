import 'dart:typed_data';

import 'package:aws_encryption_sdk/aws_encryption_sdk.dart';
import 'package:aws_encryption_sdk/src/internal/gcm.dart';
import 'package:test/test.dart';

void main() {
  group('GCM tests without Sodium', () {
    test('can encrypt', () {
      expect(encrypt(key, iv, aad, pt, SodiumPolicy.neverUseSodium), ctPlusTag);
    });

    test('can decrypt', () {
      expect(decrypt(key, iv, aad, ctPlusTag, SodiumPolicy.neverUseSodium), pt);
    });

    test('decrypt fails with bad key', () {
      final badKey = key.sublist(0);
      badKey[0] ^= 1;
      expect(
        () => decrypt(badKey, iv, aad, ctPlusTag, SodiumPolicy.neverUseSodium),
        throwsA(isA<BadCiphertextException>()),
      );
    });

    test('decrypt fails with bad iv', () {
      final badIv = iv.sublist(0);
      badIv[0] ^= 1;
      expect(
        () => decrypt(key, badIv, aad, ctPlusTag, SodiumPolicy.neverUseSodium),
        throwsA(isA<BadCiphertextException>()),
      );
    });

    test('decrypt fails with bad aad', () {
      final badAad = aad.sublist(0);
      badAad[0] ^= 1;
      expect(
        () => decrypt(key, iv, badAad, ctPlusTag, SodiumPolicy.neverUseSodium),
        throwsA(isA<BadCiphertextException>()),
      );
    });
  });

  group('GCM tests with Sodium', () {
    test('can encrypt', () {
      expect(encrypt(key, iv, aad, pt, SodiumPolicy.requireSodium), ctPlusTag);
    });

    test('can decrypt', () {
      expect(decrypt(key, iv, aad, ctPlusTag, SodiumPolicy.requireSodium), pt);
    });

    test('decrypt fails with bad key', () {
      final badKey = key.sublist(0);
      badKey[0] ^= 1;
      expect(
        () => decrypt(badKey, iv, aad, ctPlusTag, SodiumPolicy.requireSodium),
        throwsA(isA<BadCiphertextException>()),
      );
    });

    test('decrypt fails with bad iv', () {
      final badIv = iv.sublist(0);
      badIv[0] ^= 1;
      expect(
        () => decrypt(key, badIv, aad, ctPlusTag, SodiumPolicy.requireSodium),
        throwsA(isA<BadCiphertextException>()),
      );
    });

    test('decrypt fails with bad aad', () {
      final badAad = aad.sublist(0);
      badAad[0] ^= 1;
      expect(
        () => decrypt(key, iv, badAad, ctPlusTag, SodiumPolicy.requireSodium),
        throwsA(isA<BadCiphertextException>()),
      );
    });
  });

  // todo - out and back with and without?
}

final key = Uint8List.fromList([
  0xee,
  0xbc,
  0x1f,
  0x57,
  0x48,
  0x7f,
  0x51,
  0x92,
  0x1c,
  0x04,
  0x65,
  0x66,
  0x5f,
  0x8a,
  0xe6,
  0xd1,
  0x65,
  0x8b,
  0xb2,
  0x6d,
  0xe6,
  0xf8,
  0xa0,
  0x69,
  0xa3,
  0x52,
  0x02,
  0x93,
  0xa5,
  0x72,
  0x07,
  0x8f,
]);

final iv = Uint8List.fromList([
  0x99,
  0xaa,
  0x3e,
  0x68,
  0xed,
  0x81,
  0x73,
  0xa0,
  0xee,
  0xd0,
  0x66,
  0x84,
]);

final pt = Uint8List.fromList([
  0xf5,
  0x6e,
  0x87,
  0x05,
  0x5b,
  0xc3,
  0x2d,
  0x0e,
  0xeb,
  0x31,
  0xb2,
  0xea,
  0xcc,
  0x2b,
  0xf2,
  0xa5,
]);

final aad = Uint8List.fromList([
  0x4d,
  0x23,
  0xc3,
  0xce,
  0xc3,
  0x34,
  0xb4,
  0x9b,
  0xdb,
  0x37,
  0x0c,
  0x43,
  0x7f,
  0xec,
  0x78,
  0xde,
]);

final ctPlusTag = Uint8List.fromList([
  0xf7,
  0x26,
  0x44,
  0x13,
  0xa8,
  0x4c,
  0x0e,
  0x7c,
  0xd5,
  0x36,
  0x86,
  0x7e,
  0xb9,
  0xf2,
  0x17,
  0x36,
  0x67,
  0xba,
  0x05,
  0x10,
  0x26,
  0x2a,
  0xe4,
  0x87,
  0xd7,
  0x37,
  0xee,
  0x62,
  0x98,
  0xf7,
  0x7e,
  0x0c,
]);
