import 'dart:async';
import 'dart:typed_data';

abstract class Reader {
  FutureOr<Uint8List> read(int length, [allowShort = false]);

  int get available;

  FutureOr<int> readInt16() async {
    return (await read(2)).buffer.asByteData().getInt16(0);
  }

  FutureOr<int> readInt32() async {
    return (await read(4)).buffer.asByteData().getInt32(0);
  }

  FutureOr<int> readInt64() async {
    return (await read(8)).buffer.asByteData().getInt64(0);
  }
}

class BufferReader extends Reader {
  BufferReader(this._buffer) : _length = _buffer.length {
    if (_buffer.offsetInBytes != 0) {
      throw ArgumentError('input buffer has a non-zero offset');
    }
  }

  @override
  FutureOr<Uint8List> read(int length, [allowShort = false]) {
    if (length < 0) {
      throw ArgumentError('negative read request');
    }
    if (length > _length - _offset) {
      if (allowShort) {
        length = _length - _offset;
      } else {
        throw StateError('buffer underflow');
      }
    }
    final result = _buffer.sublist(_offset, _offset + length);
    _offset += length;
    return result;
  }

  @override
  int get available => _length - _offset;

  final Uint8List _buffer;
  var _offset = 0;
  final int _length;
}

class HashingReader extends Reader {
  HashingReader(this._reader);

  final Reader _reader;
  void Function(Uint8List b)? _hashFunction;

  @override
  int get available => _reader.available;

  @override
  FutureOr<Uint8List> read(int length, [allowShort = false]) async {
    final buf = await _reader.read(length, allowShort);
    if (_hashFunction != null) {
      _hashFunction!(buf);
    }
    return buf;
  }

  void setDigestFunction(
    void Function(Uint8List b)? hashFunction, [
    List<Uint8List> backlog = const [],
  ]) {
    _hashFunction = hashFunction;
    if (hashFunction != null) {
      for (final b in backlog) {
        hashFunction(b);
      }
    }
  }

/*
  Uint8List get hash {
    if (_digest == null) {
      throw StateError('hash called when digest is null');
    }
    _enabled = false;
    final hash = Uint8List(_digest!.digestSize);
    _digest!.doFinal(hash, 0);
    return hash;
  }*/
}

class StreamReader extends Reader {
  StreamReader(Stream<List<int>> stream) {
    _subscription = stream.listen(
      _onData,
      onDone: _onDone,
      onError: _onError,
      cancelOnError: true, // todo??
    );
  }

  void _onData(List<int> data) {
    // todo - is the following safe? depends if the incoming list is re-used
    //_buffers.add(data is Uint8List ? data : Uint8List.fromList(data));
    _buffers.add(Uint8List.fromList(data));
    _available += data.length;

    _completer?.complete();
  }

  @override
  Future<Uint8List> read(int length, [allowShort = false]) async {
    if (length < 0) {
      throw ArgumentError('negative read request');
    }

    while (length > _available) {
      if (_done) {
        if (allowShort) {
          length = _available;
          break;
        } else {
          throw Exception('underflow');
        }
      }

      if (_completer != null) {
        throw StateError('completer in wrong state');
      }

      _completer = Completer();
      await _completer!.future;
      _completer = null;
    }

    // got enough
    var data = Uint8List(length);
    var soFar = 0;
    while (soFar < length) {
      final toGo = length - soFar;
      final buffer = _buffers.removeAt(0);
      var bufferLength = buffer.length;
      if (bufferLength <= toGo) {
        // use all of it
        data.setRange(soFar, soFar + bufferLength, buffer);
        soFar += bufferLength;
      } else {
        // use part
        // todo - make this more efficient
        data.setRange(soFar, soFar + toGo, buffer);
        soFar += toGo;
        // and re-insert the remnant
        _buffers.insert(0, buffer.sublist(toGo));
      }
    }

    _available -= length;
    return data;
  }

  @override
  int get available => _available;

  void _onDone() {
    _done = true;
    _completer?.complete();
  }

  void _onError(error, StackTrace stackTrace) {
    print('ooops $error'); // todo
  }

  // ignore: unused_field
  late StreamSubscription<List<int>> _subscription; // todo - use to pause

  final _buffers = <Uint8List>[];
  var _available = 0;

  var _done = false;

  Completer? _completer;
}
