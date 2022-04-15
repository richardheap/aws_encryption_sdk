import 'package:aws_encryption_sdk/src/model/frame_headers.dart';
import 'package:test/test.dart';

void main() {
  //final throwsAws = throwsA(isA<AwsCryptoException>());
  //final throwsBcte = throwsA(isA<BadCiphertextException>());

  group('Frame Header tests', () {
    test('can encode and decode', () {
      final f1 = FrameHeaders.forEncryption(1, false, 4096);
      final fs1 = f1.serialize();

      final f2 = FrameHeaders();
      //f2.deserialize(r, 12, tagLength, 4096, 2);

    });
  });
}