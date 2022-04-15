import 'dart:typed_data';

import 'package:aws_encryption_sdk/aws_encryption_sdk.dart';
import 'package:aws_encryption_sdk/src/internal/encryption_context_codec.dart';
import 'package:test/test.dart';

void main() {
  final throwsAws = throwsA(isA<AwsCryptoException>());
  final throwsBcte = throwsA(isA<BadCiphertextException>());

  group('Context Codec tests', () {
    test('can encode and decode', () {
      final context = {'a': 'bb', 'ccc': 'dddd'};
      final encoded = serializeEncryptionContext(context);
      final result = deserializeEncryptionContext(encoded);

      expect(result, completion(equals(context)));
    });

    test('encodes null correctly', () {
      expect(serializeEncryptionContext(null), Uint8List(0));
    });

    test('encodes empty correctly', () {
      expect(serializeEncryptionContext({}), Uint8List(0));
    });

    test('decodes empty correctly', () {
      expect(
        deserializeEncryptionContext(Uint8List(0)),
        completion(equals({})),
      );
    });

    test('rejects empty value', () {
      expect(
        () => serializeEncryptionContext({'key': ''}),
        throwsAws,
      );
    });

    test('rejects empty key', () {
      expect(
        () => serializeEncryptionContext({'': 'value'}),
        throwsAws,
      );
    });

    test('rejects bad overall length 1', () {
      expect(
        () => deserializeEncryptionContext(Uint8List.fromList([0, 0])),
        throwsBcte,
      );
    });

    test('rejects bad overall length 2', () {
      expect(
        () => deserializeEncryptionContext(Uint8List.fromList([0, 1, 0, 0])),
        throwsBcte,
      );
    });

    test('detects bad value length', () {
      final encoded = serializeEncryptionContext({'abc': 'def'});
      encoded[7] = 0xff;
      encoded[8] = 0xff;
      expect(() => deserializeEncryptionContext(encoded), throwsBcte);
    });

    test('detects bad unicode', () {
      final encoded = serializeEncryptionContext({'abc': 'def'});
      encoded[5] = 0x80;
      expect(() => deserializeEncryptionContext(encoded), throwsBcte);
    });

    test('detects buffer underflow', () {
      final encoded = serializeEncryptionContext({'abc': 'def'});
      expect(
        () => deserializeEncryptionContext(
          encoded.sublist(0, encoded.length - 1),
        ),
        throwsBcte,
      );
    });
    // todo - unicode, etc
  });
}
