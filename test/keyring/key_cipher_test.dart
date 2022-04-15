import 'dart:typed_data';

import 'package:aws_encryption_sdk/src/keyring/raw_aes_keyring.dart';
import 'package:test/test.dart';

void main() {
  group('AES key cipher tests', () {
    test('Out and back', () {
      final akc = AesKeyCipher(Uint8List.fromList([
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
      ]));

      final plain = Uint8List.fromList([
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
      ]);

      final ec = {
        'a': 'bb',
        'ccc': 'dddd',
      };

      final edk = akc.encryptKey(plain, 'test', 'testNs', ec);

      expect(edk.encryptedDataKey.length, 48);

      expect(akc.decryptKey(edk, 'test', ec), plain);

      ec['a'] = 'BB';
      expect(() => akc.decryptKey(edk, 'test', ec), throwsException);
    });
  });
}
