import 'dart:typed_data';

import '../crypto_algorithm.dart';
import '../exception/exceptions.dart';
import '../internal/encryption_context_codec.dart';
import '../internal/trailing_signature_algorithm.dart';
import '../util/random.dart';
import '../util/reader.dart';
import 'key_blob.dart';

class CiphertextHeaders {
  CiphertextHeaders();

  CiphertextHeaders.unsigned(
    this._cryptoAlgorithm,
    this._encryptionContext,
    this._cipherKeyBlobs,
    this._contentTypeVal,
    this._frameLength,
  ) {
    _version = 2;
    _cryptoAlgoVal = _cryptoAlgorithm.value;
    _nonce = Uint8List(_cryptoAlgorithm.nonceLengthBytes);
    _messageId = makeRandom(_cryptoAlgorithm.messageIdLength);
    _encryptionContextLength = _encryptionContext.length;
  }

  Future<void> deserialize(Reader r) async {
    _version = await _readByte(r);
    if (_version != 2) {
      throw AwsCryptoException('only v2 message format supported');
    }

    _cryptoAlgoVal = await r.readInt16();
    try {
      _cryptoAlgorithm = CryptoAlgorithmUtils.byValue(_version, _cryptoAlgoVal);
    } catch (e) {
      throw BadCiphertextException('unsupported algorithm id');
    }

    if (_cryptoAlgorithm.trailingSignatureLength > 0) {
      // enable hashing
      if (r is HashingReader) {
        final backlog = Uint8List(3)
          ..buffer.asByteData().setUint8(0, _version)
          ..buffer.asByteData().setInt16(1, _cryptoAlgoVal);
        _trailingSignatureAlgorithm =
            TrailingSignatureAlgorithm.fromAlgorithm(_cryptoAlgorithm);
        r.setDigestFunction(
          _trailingSignatureAlgorithm!.updateHash,
          [backlog],
        );
      } else {
        throw AwsCryptoException('unwrapped reader');
      }
    }

    _configV2();

    await _parseMessageId(r);
    await _parseEncryptionContextLength(r);
    await _readEncryptionContext(r);

    final edkCount = await r.readInt16();
    if (edkCount < 1) {
      throw BadCiphertextException('corrupt key count');
      // todo compare to max encrypted keys
    }
    _cipherKeyBlobs = List<KeyBlob?>.filled(
      edkCount,
      null,
      growable: false,
    );
    for (var i = 0; i < edkCount; i++) {
      _cipherKeyBlobs[i] = await KeyBlob.deserialize(r);
    }

    _contentTypeVal = await _readByte(r);
    _frameLength = await r.readInt32();
    suiteData = await r.read(_suiteDataLength);
    _headerTag = await r.read(_cryptoAlgorithm.tagLengthBytes);
  }

  Uint8List serializeAuthenticatedFields() {
    final builder = BytesBuilder(copy: true)
      ..addByte(_version)
      ..add(_putShort(_cryptoAlgoVal))
      ..add(_messageId)
      ..add(_putUnsignedShort(_encryptionContextLength));

    if (_encryptionContextLength > 0) {
      builder.add(_encryptionContext);
    }

    builder.add(_putShort(_cipherKeyBlobs.length));

    for (final blob in _cipherKeyBlobs) {
      builder.add(blob!.toBytes());
    }

    builder
      ..addByte(_contentTypeVal)
      ..add(_putInt(_frameLength))
      ..add(suiteData);

    return builder.toBytes();
  }

  Future<int> _readByte(Reader r) async => (await r.read(1))[0] & 0xff;

  Uint8List _putShort(int s) =>
      Uint8List(2)..buffer.asByteData().setInt16(0, s);

  Uint8List _putUnsignedShort(int s) =>
      Uint8List(2)..buffer.asByteData().setUint16(0, s);

  Uint8List _putInt(int s) => Uint8List(4)..buffer.asByteData().setInt32(0, s);

  void _configV2() {
    _suiteDataLength = _cryptoAlgorithm.suiteDataLength;
    _nonce = _cryptoAlgorithm.nonce;
    _nonceLength = _nonce != null ? _nonce!.length : -1;
  }

  Future<void> _parseMessageId(Reader r) async {
    final messageIdLen = _cryptoAlgorithm.messageIdLength;
    _messageId = await r.read(messageIdLen);
  }

  Future<void> _parseEncryptionContextLength(Reader r) async {
    _encryptionContextLength = await r.readInt16();
    if (_encryptionContextLength < 0) {
      throw BadCiphertextException(
        'Invalid encryption context length in ciphertext',
      );
    }
  }

  Future<void> _readEncryptionContext(Reader r) async {
    _encryptionContext = await r.read(_encryptionContextLength);
  }

  List<KeyBlob> get keyBlobs => _cipherKeyBlobs.cast<KeyBlob>();

  Future<Map<String, String>> parseEncryptionContext() =>
      deserializeEncryptionContext(_encryptionContext);

  CryptoAlgorithm get cryptoAlgorithm => _cryptoAlgorithm;

  Uint8List get messageId => _messageId;

  Uint8List get headerTag => _headerTag!;

  set headerTag(Uint8List tag) => _headerTag = tag;

  int get nonceLength => _nonceLength;

  int get frameLength => _frameLength;

  int get contentType => _contentTypeVal;

  TrailingSignatureAlgorithm? get trailingSignatureAlgorithm =>
      _trailingSignatureAlgorithm;

  TrailingSignatureAlgorithm? _trailingSignatureAlgorithm;

  var _version = -1;
  var _cryptoAlgoVal = -1;
  late CryptoAlgorithm _cryptoAlgorithm;
  var _suiteDataLength = -1;
  Uint8List? _nonce;
  var _nonceLength = -1;
  late Uint8List _messageId;
  var _encryptionContextLength = -1;
  var _encryptionContext = Uint8List(0);
  var _cipherKeyBlobs = <KeyBlob?>[];
  var _contentTypeVal = -1;
  var _frameLength = -1;
  late Uint8List suiteData;
  Uint8List? _headerTag;
}
