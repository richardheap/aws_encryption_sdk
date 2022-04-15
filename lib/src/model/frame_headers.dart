import 'dart:typed_data';

import '../exception/exceptions.dart';
import '../util/reader.dart';

class FrameHeaders {
  FrameHeaders();

  FrameHeaders.forEncryption(
    this._sequenceNumber,
    this._isFinalFrame,
    this._frameContentLength,
  ) {
    _nonce = Uint8List(12)..buffer.asByteData().setInt32(8, _sequenceNumber);
  }

  var _sequenceNumber = 0;
  var _isFinalFrame = false;
  late final Uint8List _nonce;
  late final int _frameContentLength;
  late final Uint8List _frameWithTag;

  int get sequenceNumber => _sequenceNumber;

  bool get isFinalFrame => _isFinalFrame;

  Uint8List get nonce => _nonce;

  int get frameContentLength => _frameContentLength;

  Uint8List get frameWithTag => _frameWithTag;

  Uint8List serialize() {
    if (_isFinalFrame) {
      final bytes = Uint8List(24);
      bytes.buffer.asByteData()
        ..setInt32(0, -1)
        ..setInt32(4, _sequenceNumber)
        ..setInt32(20, _frameContentLength);
      bytes.setRange(8, 20, _nonce);
      return bytes;
    } else {
      final bytes = Uint8List(16);
      bytes.buffer.asByteData().setInt32(0, _sequenceNumber);
      bytes.setRange(4, 16, _nonce);
      return bytes;
    }
  }

  Future<void> deserialize(
    Reader r,
    int nonceLength,
    int tagLength,
    int defaultFrameLength,
    int frameType,
  ) async {
    if (frameType == 1) {
      // unframed
      if (nonceLength > 0) {
        _nonce = await r.read(nonceLength);
      }

      _frameContentLength = await r.readInt64();
      if (_frameContentLength < 0) {
        throw BadCiphertextException('negative frame length');
      }

      _isFinalFrame = true;
      _sequenceNumber = 1;
    } else {
      // framed
      _sequenceNumber = await r.readInt32();
      if (_sequenceNumber == -1 && !_isFinalFrame) {
        _isFinalFrame = true;
        _sequenceNumber = await r.readInt32();
      }

      if (nonceLength > 0) {
        _nonce = await r.read(nonceLength);
      }

      _frameContentLength =
          _isFinalFrame ? await r.readInt32() : defaultFrameLength;
      if (_frameContentLength < 0) {
        throw BadCiphertextException('negative frame length');
      }
    }
    _frameWithTag = await r.read(_frameContentLength + tagLength);
  }
}
