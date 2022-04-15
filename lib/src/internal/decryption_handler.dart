import 'dart:typed_data';

import '../crypto_algorithm.dart';
import '../exception/exceptions.dart';
import '../material/default_materials_manager.dart';
import '../model/ciphertext_footer.dart';
import '../model/ciphertext_headers.dart';
import '../model/frame_headers.dart';
import '../util/reader.dart';
import 'constants.dart';
import 'gcm.dart';
import 'trailing_signature_algorithm.dart';
import 'utils.dart';

class DecryptionHandler {
  DecryptionHandler(
    this._materialsManager,
    this._headers,
    this._maxEncryptedDataKeys,
  ) {
    _cryptoAlgorithm = _headers.cryptoAlgorithm;
    _messageId = _headers.messageId;

    if (_maxEncryptedDataKeys > 0 &&
        _headers.keyBlobs.length > _maxEncryptedDataKeys) {
      throw AwsCryptoException(
        'Ciphertext encrypted data keys exceed maxEncryptedDataKeys',
      );
    }
  }

  final MaterialsManager _materialsManager;
  final CiphertextHeaders _headers;

  late final CryptoAlgorithm _cryptoAlgorithm;
  late final Uint8List _messageId;
  late final int _nonceLength;
  late final int _tagLength;
  late final int _frameLength;
  late final Map<String, String> encryptionContext;

  late final Uint8List _decryptionKey;
  late final TrailingSignatureAlgorithm? _trailingSignatureAlgorithm;

  final int _maxEncryptedDataKeys;

  Future<void> init() async {
    // make a copy as [decryptMaterials] will remove the signature public key
    // and we want to keep that reduced map
    encryptionContext = await _headers.parseEncryptionContext();
    _trailingSignatureAlgorithm = _headers.trailingSignatureAlgorithm;

    final materials = await _materialsManager.decryptMaterials(
      _headers.cryptoAlgorithm,
      encryptionContext,
      _headers.keyBlobs,
      _headers.trailingSignatureAlgorithm,
    );

    _decryptionKey = _cryptoAlgorithm.getEncryptionKeyFromDataKey(
      materials.unencryptedDataKey,
      _headers,
    );

    _nonceLength = _headers.nonceLength;
    _tagLength = _cryptoAlgorithm.tagLengthBytes;
    _frameLength = _headers.frameLength;
    final contentType = _headers.contentType;
    if (contentType != 1 && contentType != 2) {
      throw UnimplementedError('unsupported frame type');
    }

    _verifyHeaderIntegrity(_headers);
  }

  Future<Uint8List> processFrames(Reader r) async {
    final contentType = _headers.contentType;
    final builder = BytesBuilder();
    while (true) {
      final frameHeaders = FrameHeaders();
      await frameHeaders.deserialize(
        r,
        _nonceLength,
        _tagLength,
        _frameLength,
        contentType,
      );
      builder.add(_decryptFrameContent(
        frameHeaders.frameWithTag,
        frameHeaders.isFinalFrame,
        frameHeaders.sequenceNumber,
        frameHeaders.frameContentLength,
        frameHeaders.nonce,
        contentType,
      ));

      if (frameHeaders.isFinalFrame) {
        break;
      }
    }

    final trailingSignatureLength = _cryptoAlgorithm.trailingSignatureLength;
    if (trailingSignatureLength > 0) {
      await _verifyTrailingSignature(r, trailingSignatureLength);
    }

    return builder.toBytes();
  }

  Stream<Uint8List> processStream(Reader r) async* {
    final contentType = _headers.contentType;
    while (true) {
      final frameHeaders = FrameHeaders();
      await frameHeaders.deserialize(
        r,
        _nonceLength,
        _tagLength,
        _frameLength,
        contentType,
      );
      yield _decryptFrameContent(
        frameHeaders.frameWithTag,
        frameHeaders.isFinalFrame,
        frameHeaders.sequenceNumber,
        frameHeaders.frameContentLength,
        frameHeaders.nonce,
        contentType,
      );

      if (frameHeaders.isFinalFrame) {
        break;
      }
    }

    final trailingSignatureLength = _cryptoAlgorithm.trailingSignatureLength;
    if (trailingSignatureLength > 0) {
      await _verifyTrailingSignature(r, trailingSignatureLength);
    }
  }

  Uint8List _decryptFrameContent(
    Uint8List input,
    bool isFinalFrame,
    int seqNum,
    int length,
    Uint8List nonce,
    int contentType,
  ) {
    final idString = contentType == 1
        ? singleBlockStringId
        : isFinalFrame
            ? finalFrameStringId
            : frameStringId;
    final aad = generateContentAad(
      _messageId,
      idString,
      seqNum,
      length,
    );

    try {
      return decrypt(_decryptionKey, nonce, aad, input);
    } catch (e) {
      throw BadCiphertextException(e.toString());
    }
  }

  void _verifyHeaderIntegrity(final CiphertextHeaders ciphertextHeaders) {
    decrypt(
      _decryptionKey,
      Uint8List(12),
      _headers.serializeAuthenticatedFields(),
      _headers.headerTag,
    ); // throws on error
  }

  Future<void> _verifyTrailingSignature(
    Reader r,
    int trailingSignatureLength,
  ) async {
    if (r is! HashingReader) {
      throw AwsCryptoException('not a hashing reader');
    }

    // stop the reader collecting the hash before reading the footer
    r.setDigestFunction(null);

    final footer = CiphertextFooter();
    try {
      await footer.deserialize(r, trailingSignatureLength);
    } catch (e) {
      throw BadCiphertextException(e.toString());
    }

    if (!_trailingSignatureAlgorithm!.verify(footer.sigBytes)) {
      throw BadCiphertextException('bad trailing signature');
    }
  }
}
