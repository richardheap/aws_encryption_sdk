import 'dart:typed_data';

import 'package:aws_encryption_sdk/aws_encryption_sdk.dart';
import 'package:aws_encryption_sdk/src/util/random.dart';
import 'package:test/test.dart';

void main() {
  final throwsAws = throwsA(isA<AwsCryptoException>());

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

    test('can encode and decode with 256, signed', () async {
      final keyring = keyring256;

      var plaintext = shortPlaintext;
      expect(
        await _roundTrip(awsCrypto, plaintext, keyring, encryptionContext),
        plaintext,
      );

      plaintext = exactPlaintext;
      expect(
        await _roundTrip(awsCrypto, plaintext, keyring, encryptionContext),
        plaintext,
      );

      plaintext = longPlaintext;
      expect(
        await _roundTrip(awsCrypto, plaintext, keyring, encryptionContext),
        plaintext,
      );
    });

    test('using a bad key fails to decrypt', () async {
      var plaintext = shortPlaintext;
      final keyring = keyring256;

      expect(
        Future.sync(() async {
          await _roundTrip(
            awsCrypto,
            plaintext,
            keyring,
            encryptionContext,
            true,
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

    test('can encode and decode with 256, unsigned', () async {
      final keyring = keyring256;

      var plaintext = shortPlaintext;
      expect(
        await _roundTrip(awsCrypto, plaintext, keyring, encryptionContext),
        plaintext,
      );

      plaintext = exactPlaintext;
      expect(
        await _roundTrip(awsCrypto, plaintext, keyring, encryptionContext),
        plaintext,
      );

      plaintext = longPlaintext;
      expect(
        await _roundTrip(awsCrypto, plaintext, keyring, encryptionContext),
        plaintext,
      );
    });
  });
}

Future<Uint8List?> _roundTrip(
  AwsCrypto awsCrypto,
  Uint8List plaintext,
  Keyring keyring,
  Map<String, String> encryptionContext, [
  bool bad = false,
]) async {
  // encrypt
  final encryptionResult = await awsCrypto.encryptStream(
    stream: _plaintextAsStream(plaintext),
    keyring: keyring,
    encryptionContext: encryptionContext,
  );

  // decrypt
  final decryptionResult = await awsCrypto.decryptStream(
    stream: encryptionResult.stream,
    keyring: bad ? _badKeyring() : keyring,
  );

  final decryptedContext = decryptionResult.encryptionContext;
  if (decryptedContext.length != encryptionContext.length) {
    return null;
  }
  for (final k in decryptedContext.keys) {
    if (decryptedContext[k] != encryptionContext[k]) {
      return null;
    }
  }

  final builder = BytesBuilder();
  await for (final b in decryptionResult.stream) {
    builder.add(b);
  }
  return builder.takeBytes();
}

Keyring _badKeyring() => RawAesKeyring(
      'ns',
      'aes256',
      Uint8List(32),
      WrappingAlgorithm.aes256GcmIv12Tag16NoPadding,
    );

Stream<Uint8List> _plaintextAsStream(Uint8List pt) async* {
  yield pt;
}
