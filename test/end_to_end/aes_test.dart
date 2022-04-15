import 'dart:typed_data';

import 'package:aws_encryption_sdk/aws_encryption_sdk.dart';
import 'package:aws_encryption_sdk/src/util/random.dart';
import 'package:test/test.dart';

void main() {
  final throwsAws = throwsA(isA<AwsCryptoException>());

  final keyring128 = RawAesKeyring(
    'ns',
    'aes128',
    makeRandom(16),
    WrappingAlgorithm.aes128GcmIv12Tag16NoPadding,
  );

  final keyring192 = RawAesKeyring(
    'ns',
    'aes192',
    makeRandom(24),
    WrappingAlgorithm.aes192GcmIv12Tag16NoPadding,
  );

  final keyring256 = RawAesKeyring(
    'ns',
    'aes256',
    makeRandom(32),
    WrappingAlgorithm.aes256GcmIv12Tag16NoPadding,
  );

  final encryptionContext = {
    'example key': 'example value',
    'another key': 'and another value',
  };

  final shortPlaintext = makeRandom(128);
  final exactPlaintext = makeRandom(4096);
  final longPlaintext = makeRandom(10000);

  group('End to end aes tests, single chunk, signed', () {
    final awsCrypto = AwsCrypto();

    test('can encode and decode with 128, signed', () async {
      final keyring = keyring128;

      var plaintext = shortPlaintext;
      var decResult = await roundTrip(
        awsCrypto,
        plaintext,
        keyring,
        encryptionContext,
      );
      expect(decResult.encryptionContext, encryptionContext);
      expect(decResult.result, plaintext);

      plaintext = exactPlaintext;
      decResult = await roundTrip(
        awsCrypto,
        plaintext,
        keyring,
        encryptionContext,
      );
      expect(decResult.encryptionContext, encryptionContext);
      expect(decResult.result, plaintext);

      plaintext = longPlaintext;
      decResult = await roundTrip(
        awsCrypto,
        plaintext,
        keyring,
        encryptionContext,
      );
      expect(decResult.encryptionContext, encryptionContext);
      expect(decResult.result, plaintext);
    });

    test('can encode and decode with 192, signed', () async {
      final keyring = keyring192;

      var plaintext = shortPlaintext;
      var decResult = await roundTrip(
        awsCrypto,
        plaintext,
        keyring,
        encryptionContext,
      );
      expect(decResult.encryptionContext, encryptionContext);
      expect(decResult.result, plaintext);

      plaintext = exactPlaintext;
      decResult = await roundTrip(
        awsCrypto,
        plaintext,
        keyring,
        encryptionContext,
      );
      expect(decResult.encryptionContext, encryptionContext);
      expect(decResult.result, plaintext);

      plaintext = longPlaintext;
      decResult = await roundTrip(
        awsCrypto,
        plaintext,
        keyring,
        encryptionContext,
      );
      expect(decResult.encryptionContext, encryptionContext);
      expect(decResult.result, plaintext);
    });

    test('can encode and decode with 256, signed', () async {
      final keyring = keyring256;

      var plaintext = shortPlaintext;
      var decResult = await roundTrip(
        awsCrypto,
        plaintext,
        keyring,
        encryptionContext,
      );
      expect(decResult.encryptionContext, encryptionContext);
      expect(decResult.result, plaintext);

      plaintext = exactPlaintext;
      decResult = await roundTrip(
        awsCrypto,
        plaintext,
        keyring,
        encryptionContext,
      );
      expect(decResult.encryptionContext, encryptionContext);
      expect(decResult.result, plaintext);

      plaintext = longPlaintext;
      decResult = await roundTrip(
        awsCrypto,
        plaintext,
        keyring,
        encryptionContext,
      );
      expect(decResult.encryptionContext, encryptionContext);
      expect(decResult.result, plaintext);
    });

    test('using a bad key fails to decrypt', () async {
      final encResult = await awsCrypto.encryptData(
        data: shortPlaintext,
        keyring: keyring128,
        encryptionContext: encryptionContext,
      );

      expect(
        Future.sync(() async {
          await awsCrypto.decryptData(
            data: encResult.result,
            keyring: RawAesKeyring(
              'ns',
              'aes128',
              Uint8List(16), // bad key
              WrappingAlgorithm.aes128GcmIv12Tag16NoPadding,
            ),
          );
        }),
        throwsAws,
      );
    });
  });

  group('End to end aes tests, single chunk, unsigned', () {
    final awsCrypto = AwsCrypto(
      encryptionAlgorithm: CryptoAlgorithm.algAes256GcmHkdfSha512CommitKey,
    );

    test('can encode and decode with 128, unsigned', () async {
      final keyring = keyring128;

      var plaintext = shortPlaintext;
      var decResult = await roundTrip(
        awsCrypto,
        plaintext,
        keyring,
        encryptionContext,
      );
      expect(decResult.encryptionContext, encryptionContext);
      expect(decResult.result, plaintext);

      plaintext = exactPlaintext;
      decResult = await roundTrip(
        awsCrypto,
        plaintext,
        keyring,
        encryptionContext,
      );
      expect(decResult.encryptionContext, encryptionContext);
      expect(decResult.result, plaintext);

      plaintext = longPlaintext;
      decResult = await roundTrip(
        awsCrypto,
        plaintext,
        keyring,
        encryptionContext,
      );
      expect(decResult.encryptionContext, encryptionContext);
      expect(decResult.result, plaintext);
    });

    test('can encode and decode with 192, unsigned', () async {
      final keyring = keyring192;

      var plaintext = shortPlaintext;
      var decResult = await roundTrip(
        awsCrypto,
        plaintext,
        keyring,
        encryptionContext,
      );
      expect(decResult.encryptionContext, encryptionContext);
      expect(decResult.result, plaintext);

      plaintext = exactPlaintext;
      decResult = await roundTrip(
        awsCrypto,
        plaintext,
        keyring,
        encryptionContext,
      );
      expect(decResult.encryptionContext, encryptionContext);
      expect(decResult.result, plaintext);

      plaintext = longPlaintext;
      decResult = await roundTrip(
        awsCrypto,
        plaintext,
        keyring,
        encryptionContext,
      );
      expect(decResult.encryptionContext, encryptionContext);
      expect(decResult.result, plaintext);
    });

    test('can encode and decode with 256, unsigned', () async {
      final keyring = keyring256;

      var plaintext = shortPlaintext;
      var decResult = await roundTrip(
        awsCrypto,
        plaintext,
        keyring,
        encryptionContext,
      );
      expect(decResult.encryptionContext, encryptionContext);
      expect(decResult.result, plaintext);

      plaintext = exactPlaintext;
      decResult = await roundTrip(
        awsCrypto,
        plaintext,
        keyring,
        encryptionContext,
      );
      expect(decResult.encryptionContext, encryptionContext);
      expect(decResult.result, plaintext);

      plaintext = longPlaintext;
      decResult = await roundTrip(
        awsCrypto,
        plaintext,
        keyring,
        encryptionContext,
      );
      expect(decResult.encryptionContext, encryptionContext);
      expect(decResult.result, plaintext);
    });
  });
}

Future<CryptoResult> roundTrip(
  AwsCrypto awsCrypto,
  Uint8List plaintext,
  Keyring keyring,
  Map<String, String> encryptionContext,
) async {
  final encResult = await awsCrypto.encryptData(
    data: plaintext,
    keyring: keyring,
    encryptionContext: encryptionContext,
  );
  return await awsCrypto.decryptData(
    data: encResult.result,
    keyring: keyring,
  );
}
