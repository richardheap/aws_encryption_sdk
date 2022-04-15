import 'dart:convert';
import 'dart:typed_data';

import 'package:aws_encryption_sdk/src/crypto_algorithm.dart';
import 'package:aws_encryption_sdk/src/internal/committed_key.dart';
import 'package:test/test.dart';

void main() {
  group('Committed Key tests', () {
    // these vectors are from the Typescript impl tests
    final messageWithCommitKeyMessageIdBase64 =
        'TfvRMU2dVZJbgXIyxeNtbj5eIw8BiTDiwsHyQ/Z9wXk=';
    final messageWithCommitKeyCommitmentBase64 =
        'F88I9zPbUQSfOlzLXv+uIY2+m/E6j2PMsbgeHVH/L0w=';
    final messageWithCommitKeyDEKBase64 =
        '+p6+whPVw9kOrYLZFMRBJ2n6Vli6T/7TkjDouS+25s0=';
    final expectedKeyBase64 = 'V67301yMJtk0jxOc3QJeBac6uKxO3XylWtkKTYmUU+M=';
    final algo = CryptoAlgorithm.algAes256GcmHkdfSha512CommitKey;

    test('Generate', () {
      final key = base64.decode(messageWithCommitKeyDEKBase64);
      final id = base64.decode(messageWithCommitKeyMessageIdBase64);

      final ck = CommittedKey.generate(algo, key, id);

      expect(
        ck.commitment,
        base64.decode(messageWithCommitKeyCommitmentBase64),
      );
      expect(ck.ek, base64.decode(expectedKeyBase64));
    });

    test('Generate bad nonce length', () {
      final key = base64.decode(messageWithCommitKeyDEKBase64);
      expect(
        () => CommittedKey.generate(
          algo,
          key,
          Uint8List(algo.commitmentNonceLength + 1),
        ),
        throwsStateError,
      );
    });

    test('detect bad parameters', () {
      () => CommittedKey.generate(
            algo,
            Uint8List(10),
            Uint8List(algo.commitmentNonceLength),
          );
    });
  });
}
