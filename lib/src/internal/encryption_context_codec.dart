import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';

import '../exception/exceptions.dart';
import '../util/reader.dart';
import '../util/uint8list_compare.dart';

const int _shortMax = 0x7fff;

Uint8List serializeEncryptionContext(Map<String, String>? encryptionContext) {
  if (encryptionContext == null) {
    return Uint8List(0);
  }

  if (encryptionContext.isEmpty) {
    return Uint8List(0);
  }

  if (encryptionContext.length > _shortMax) {
    throw AwsCryptoException(
      'The number of entries in encryption context exceeds the maximum',
    );
  }

  var totalLength = 2;
  final binaryMap = SplayTreeMap<Uint8List, Uint8List>(unsignedByteListCompare);
  for (final entry in encryptionContext.entries) {
    if (entry.key.isEmpty || entry.value.isEmpty) {
      throw AwsCryptoException(
        'All keys and values in encryption context must not be nonempty',
      );
    }

    final key = utf8.encode(entry.key);
    final value = utf8.encode(entry.value);

    if (key.length > _shortMax || value.length > _shortMax) {
      throw AwsCryptoException(
        'All keys and values in encryption context must be shorter than 32768',
      );
    }
    totalLength += 4 + key.length + value.length;

    if (binaryMap.containsKey(key)) {
      throw AwsCryptoException(
        'Encryption context contains duplicate entries.',
      );
    }
    binaryMap[key] = value;
  }

  final result = Uint8List(totalLength);
  var offset = 0;
  // all operations will be big endian
  final bd = result.buffer.asByteData();
  bd.setInt16(offset, binaryMap.length);
  offset += 2;

  for (final entry in binaryMap.entries) {
    var l = entry.key.length;
    bd.setInt16(offset, l);
    offset += 2;

    result.setRange(offset, offset + l, entry.key);
    offset += l;

    l = entry.value.length;
    bd.setInt16(offset, l);
    offset += 2;

    result.setRange(offset, offset + l, entry.value);
    offset += l;
  }

  return result;
}

Future<Map<String, String>> deserializeEncryptionContext(Uint8List b) async {
  if (b.isEmpty) {
    return <String, String>{};
  }

  final r = BufferReader(b);

  try {
    final count = await r.readInt16();
    if (count <= 0) {
      throw BadCiphertextException(
        'The number of entries in encryption context must be greater than 0',
      );
    }

    final result = <String, String>{};
    for (var i = 0; i < count; i++) {
      final keyLength = await r.readInt16();
      if (keyLength <= 0) {
        throw BadCiphertextException('Key length must be greater than 0');
      }
      final k = _safeUtf8Decode(await r.read(keyLength));

      final valueLength = await r.readInt16();
      if (valueLength <= 0) {
        throw BadCiphertextException('Value length must be greater than 0');
      }
      final v = _safeUtf8Decode(await r.read(valueLength));

      result[k] = v;
    }

    return result;
  } on StateError {
    throw BadCiphertextException('corrupt encryption context');
  }
}

String _safeUtf8Decode(Uint8List b) {
  try {
    return utf8.decode(b);
  } catch (e) {
    throw BadCiphertextException('invalid utf8 in encryption context');
  }
}
