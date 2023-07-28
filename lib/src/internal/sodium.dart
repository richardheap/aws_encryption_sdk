import 'dart:ffi';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

class LibSodium {
  LibSodium() {
    if (Platform.isWindows) {
      _libSodium = DynamicLibrary.open('C:\\Windows\\System32\\libsodium.dll');
    } else if (Platform.isLinux) {
      _libSodium = DynamicLibrary.open('/usr/lib64/libsodium.so.23');
    } else if (Platform.isMacOS) {
      _libSodium = DynamicLibrary.open('/usr/local/lib/libsodium.dylib');
    } else {
      throw UnsupportedError('operating system not supported');
    }

    if (_sodiumInit() != 0) {
      throw UnsupportedError('sodium init failed');
    }

    if (_isAvailable() != 1) {
      throw UnsupportedError('acceleration not available');
    }

    _inputBuffer = malloc<Uint8>(_bufferSize);
    _outputBuffer = malloc<Uint8>(_bufferSize);
    _adBuffer = malloc<Uint8>(_bufferSize);

    _keyBuffer = malloc<Uint8>(32); // 256 bit key
    _nonceBuffer = malloc<Uint8>(12); // 12 byte nonce

    _outputBufferSize = malloc<Uint64>(1); // space for the ulong*
  }

  Uint8List encrypt(
    Uint8List key,
    Uint8List nonce,
    Uint8List associatedData,
    Uint8List plaintext,
  ) {
    _copyInputs(associatedData, plaintext, key, nonce);
    final rc = _encrypt(
      _outputBuffer,
      _outputBufferSize,
      _inputBuffer,
      plaintext.length,
      _adBuffer,
      associatedData.length,
      nullptr,
      _nonceBuffer,
      _keyBuffer,
    );
    if (rc != 0) {
      throw ArgumentError('encrypt failed');
    }
    final length = _outputBufferSize.value;
    return Uint8List(length)..setAll(0, _outputBuffer.asTypedList(length));
  }

  Uint8List decrypt(
    Uint8List key,
    Uint8List nonce,
    Uint8List associatedData,
    Uint8List ciphertext,
  ) {
    _copyInputs(associatedData, ciphertext, key, nonce);
    final rc = _decrypt(
      _outputBuffer,
      _outputBufferSize,
      nullptr,
      _inputBuffer,
      ciphertext.length,
      _adBuffer,
      associatedData.length,
      _nonceBuffer,
      _keyBuffer,
    );
    if (rc != 0) {
      throw ArgumentError('decrypt failed');
    }
    final length = _outputBufferSize.value;
    return Uint8List(length)..setAll(0, _outputBuffer.asTypedList(length));
  }

  void _copyInputs(
    Uint8List associatedData,
    Uint8List input,
    Uint8List key,
    Uint8List nonce,
  ) {
    _ensureBuffers(associatedData.length, input.length);
    _keyBuffer.asTypedList(32).setAll(0, key);
    _nonceBuffer.asTypedList(12).setAll(0, nonce);
    _inputBuffer.asTypedList(_bufferSize).setAll(0, input);
    _adBuffer.asTypedList(_bufferSize).setAll(0, associatedData);
  }

  void _ensureBuffers(int l1, int l2) {
    final needed = max(l1, l2) + 32;
    if (needed > _bufferSize) {
      malloc.free(_inputBuffer);
      malloc.free(_outputBuffer);
      malloc.free(_adBuffer);
      _bufferSize = needed;
      _inputBuffer = malloc<Uint8>(_bufferSize);
      _outputBuffer = malloc<Uint8>(_bufferSize);
      _adBuffer = malloc<Uint8>(_bufferSize);
    }
  }

  late DynamicLibrary _libSodium;

  late final int Function() _sodiumInit =
      _libSodium.lookupFunction<Int32 Function(), int Function()>(
    'sodium_init',
  );

  late final int Function() _isAvailable =
      _libSodium.lookupFunction<Int32 Function(), int Function()>(
    'crypto_aead_aes256gcm_is_available',
  );

  late final int Function(
    Pointer<Uint8> c,
    Pointer<Uint64> clenP,
    Pointer<Uint8> m,
    int mlen,
    Pointer<Uint8> ad,
    int adlen,
    Pointer<Uint8> nsec,
    Pointer<Uint8> npub,
    Pointer<Uint8> k,
  ) _encrypt = _libSodium.lookupFunction<
      Int32 Function(
        Pointer<Uint8>,
        Pointer<Uint64>,
        Pointer<Uint8>,
        Uint64,
        Pointer<Uint8>,
        Uint64,
        Pointer<Uint8>,
        Pointer<Uint8>,
        Pointer<Uint8>,
      ),
      int Function(
        Pointer<Uint8>,
        Pointer<Uint64>,
        Pointer<Uint8>,
        int,
        Pointer<Uint8>,
        int,
        Pointer<Uint8>,
        Pointer<Uint8>,
        Pointer<Uint8>,
      )>('crypto_aead_aes256gcm_encrypt');

  late final int Function(
    Pointer<Uint8> m,
    Pointer<Uint64> mlenP,
    Pointer<Uint8> nsec,
    Pointer<Uint8> c,
    int clen,
    Pointer<Uint8> ad,
    int adlen,
    Pointer<Uint8> npub,
    Pointer<Uint8> k,
  ) _decrypt = _libSodium.lookupFunction<
      Int32 Function(
        Pointer<Uint8>,
        Pointer<Uint64>,
        Pointer<Uint8>,
        Pointer<Uint8>,
        Uint64,
        Pointer<Uint8>,
        Uint64,
        Pointer<Uint8>,
        Pointer<Uint8>,
      ),
      int Function(
        Pointer<Uint8>,
        Pointer<Uint64>,
        Pointer<Uint8>,
        Pointer<Uint8>,
        int,
        Pointer<Uint8>,
        int,
        Pointer<Uint8>,
        Pointer<Uint8>,
      )>('crypto_aead_aes256gcm_decrypt');

  var _bufferSize = 66000;
  late Pointer<Uint8> _inputBuffer;
  late Pointer<Uint8> _outputBuffer;
  late Pointer<Uint8> _adBuffer;
  late Pointer<Uint64> _outputBufferSize;

  late Pointer<Uint8> _keyBuffer;
  late Pointer<Uint8> _nonceBuffer;
}
