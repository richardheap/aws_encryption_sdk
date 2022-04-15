import 'dart:convert';
import 'dart:typed_data';

import '../encrypted_data_key.dart';
import '../exception/exceptions.dart';
import '../util/reader.dart';

const int _unsignedShortMax = 0xffff;

class KeyBlob extends EncryptedDataKey {
  static Future<KeyBlob> deserialize(Reader r) async {
    return KeyBlob(
      await _readChunk(r),
      await _readChunk(r),
      await _readChunk(r),
    );
  }

  static Future<Uint8List> _readChunk(Reader r) async {
    var length = await r.readInt16();
    if (length < 0) {
      throw BadCiphertextException('negative chunk length');
    }
    return r.read(length);
  }

  KeyBlob(this._keyProviderId, this._keyProviderInfo, this._encryptedKey) {
    if (_keyProviderId.length > _unsignedShortMax ||
        _keyProviderInfo.length > _unsignedShortMax ||
        _encryptedKey.length > _unsignedShortMax) {
      throw AwsCryptoException(
        'Encrypted key information exceeds'
        ' the max value of an unsigned short primitive.',
      );
    }
  }

  Uint8List toBytes() {
    final builder = BytesBuilder()
      ..add(_makeChunk(_keyProviderId))
      ..add(_makeChunk(_keyProviderInfo))
      ..add(_makeChunk(_encryptedKey));
    return builder.toBytes();
  }

  Uint8List _makeChunk(Uint8List part) => Uint8List(part.length + 2)
    ..buffer.asByteData().setInt16(0, part.length)
    ..setAll(2, part);

  final Uint8List _keyProviderId;

  final Uint8List _keyProviderInfo;

  final Uint8List _encryptedKey;

  @override
  Uint8List get encryptedDataKey => _encryptedKey;

  @override
  String get providerId => _safeUtf8Decode(_keyProviderId);

  @override
  String get providerInfoString => _safeUtf8Decode(_keyProviderInfo);

  @override
  Uint8List get providerInformation => _keyProviderInfo;

  String _safeUtf8Decode(Uint8List b) {
    try {
      return utf8.decode(b);
    } catch (e) {
      throw BadCiphertextException('invalid utf8 in key blob');
    }
  }


}
