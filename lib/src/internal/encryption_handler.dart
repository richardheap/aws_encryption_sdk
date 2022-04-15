import 'dart:typed_data';

import '../crypto_algorithm.dart';
import '../exception/exceptions.dart';
import '../material/default_materials_manager.dart';
import '../model/ciphertext_footer.dart';
import '../model/ciphertext_headers.dart';
import '../model/frame_headers.dart';
import '../util/reader.dart';
import 'committed_key.dart';
import 'constants.dart';
import 'encryption_context_codec.dart';
import 'gcm.dart';
import 'trailing_signature_algorithm.dart';
import 'utils.dart';

class EncryptionHandler {
  EncryptionHandler(
    this._materialsManager,
    this._encryptionAlgorithm,
    this._encryptionContext,
    this._encryptionFrameSize,
  );

  final MaterialsManager _materialsManager;
  final CryptoAlgorithm _encryptionAlgorithm;
  final Map<String, String> _encryptionContext;
  final int _encryptionFrameSize;

  late final Uint8List _encryptionKey;
  late final Uint8List _ciphertextHeaderBytes;
  late final Uint8List _messageId;

  //Digest? _trailingSignatureDigest;
  TrailingSignatureAlgorithm? _trailingSignatureAlgorithm;

  Future<void> init() async {
    final materials = await _materialsManager.getEncryptionMaterials(
      _encryptionAlgorithm,
      _encryptionContext,
    );

    if (materials.encryptedDataKeys.isEmpty) {
      throw AwsCryptoException('no encrypted keys available');
    }

    _trailingSignatureAlgorithm = materials.trailingSignatureAlgorithm;

    final unsignedHeaders = CiphertextHeaders.unsigned(
      _encryptionAlgorithm,
      serializeEncryptionContext(materials.encryptionContext),
      materials.encryptedDataKeys,
      2, // content type - framed
      _encryptionFrameSize,
    );

    _messageId = unsignedHeaders.messageId;

    if (_encryptionAlgorithm.isCommitting) {
      final committedKey = CommittedKey.generate(
        _encryptionAlgorithm,
        materials.plaintextDataKey!,
        _messageId,
      );
      unsignedHeaders.suiteData = committedKey.commitment;
      _encryptionKey = committedKey.ek;
    } else {
      throw UnsupportedError('v1 not supported');
    }

    final authenticatedFields = unsignedHeaders.serializeAuthenticatedFields();
    _signHeaders(unsignedHeaders, authenticatedFields);

    final builder = BytesBuilder(copy: false)
      ..add(authenticatedFields)
      ..add(unsignedHeaders.headerTag);

    _ciphertextHeaderBytes = builder.toBytes();
  }

  Future<Uint8List> processFrames(BufferReader r) async {
    final builder = BytesBuilder(copy: false);

    _appendAndDigest(_ciphertextHeaderBytes, builder);

    var sequenceNumber = 1;
    while (true) {
      final plaintext = await r.read(_encryptionFrameSize, true);
      final plaintextLength = plaintext.length;
      final finalFrame = plaintextLength != _encryptionFrameSize;

      final frameHeaders = FrameHeaders.forEncryption(
        sequenceNumber,
        finalFrame,
        plaintextLength,
      );

      _appendAndDigest(frameHeaders.serialize(), builder);

      _appendAndDigest(
        _encryptFrameContent(
          plaintext,
          finalFrame,
          sequenceNumber,
          plaintextLength,
          frameHeaders.nonce,
        ),
        builder,
      );

      if (finalFrame) {
        break;
      }

      sequenceNumber++;
    }

    if (_trailingSignatureAlgorithm != null) {
      builder.add(_generateTrailingSignature());
    }

    return builder.toBytes();
  }

  Stream<Uint8List> processStream(Reader r) async* {
    yield _digest(_ciphertextHeaderBytes);

    var sequenceNumber = 1;
    while (true) {
      final plaintext = await r.read(_encryptionFrameSize, true);
      final plaintextLength = plaintext.length;
      final finalFrame = plaintextLength != _encryptionFrameSize;

      final frameHeaders = FrameHeaders.forEncryption(
        sequenceNumber,
        finalFrame,
        plaintextLength,
      );

      yield _digest(frameHeaders.serialize());

      yield _digest(_encryptFrameContent(
        plaintext,
        finalFrame,
        sequenceNumber,
        plaintextLength,
        frameHeaders.nonce,
      ));

      if (finalFrame) {
        break;
      }

      sequenceNumber++;
    }

    if (_trailingSignatureAlgorithm != null) {
      yield _generateTrailingSignature();
    }
  }

  void _appendAndDigest(Uint8List b, BytesBuilder builder) {
    builder.add(b);
    _trailingSignatureAlgorithm?.updateHash(b);
  }

  Uint8List _digest(Uint8List b) {
    _trailingSignatureAlgorithm?.updateHash(b);
    return b;
  }

  Uint8List _encryptFrameContent(
    Uint8List input,
    bool isFinalFrame,
    int seqNum,
    int length,
    Uint8List nonce,
  ) {
    final aad = generateContentAad(
      _messageId,
      isFinalFrame ? finalFrameStringId : frameStringId,
      seqNum,
      length,
    );

    return encrypt(_encryptionKey, nonce, aad, input);
  }

  void _signHeaders(
    CiphertextHeaders unsignedHeaders,
    Uint8List authenticatedFields,
  ) {
    unsignedHeaders.headerTag = encrypt(
      _encryptionKey,
      Uint8List(12),
      authenticatedFields,
      Uint8List(0),
    );
  }

  Uint8List _generateTrailingSignature() {
    final signature = _trailingSignatureAlgorithm!.sign();
    return CiphertextFooter(signatureBytes: signature).serialize();
  }
}
