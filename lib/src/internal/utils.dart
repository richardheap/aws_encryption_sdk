import 'dart:convert';
import 'dart:typed_data';

Uint8List generateContentAad(
  Uint8List messageId,
  String idString,
  int seqNum,
  int length,
) {
  final builder = BytesBuilder()
    ..add(messageId)
    ..add(utf8.encode(idString))
    ..add(Uint8List(4)..buffer.asByteData().setInt32(0, seqNum))
    ..add(Uint8List(8)..buffer.asByteData().setInt64(0, length));

  return builder.toBytes();
}
