import 'dart:typed_data';

import '../exception/exceptions.dart';
import '../util/reader.dart';

class CiphertextFooter {
  CiphertextFooter({Uint8List? signatureBytes})
      : sigBytes = signatureBytes ?? Uint8List(0);

  Uint8List sigBytes;

  Uint8List serialize() {
    final builder = BytesBuilder(copy: false)
      ..add(Uint8List(2)..buffer.asByteData().setInt16(0, sigBytes.length))
      ..add(sigBytes);
    return builder.toBytes();
  }

  Future<void> deserialize(Reader r, trailingSignatureLength) async {
    final length = await _readShort(r);
    if (length < 0 || (length - trailingSignatureLength).abs() > 2) {
      throw BadCiphertextException('invalid signature');
    }
    sigBytes = await r.read(length);
  }

  Future<int> _readShort(Reader r) async =>
      (await r.read(2)).buffer.asByteData().getInt16(0);
}
