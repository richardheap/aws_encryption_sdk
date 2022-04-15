import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/random/fortuna_random.dart';

final _rand = Random.secure();

/// A Fortuna PRNG used throughout the code and examples for
/// key generation and cryptographically secure randomness in, for example,
/// padding.
final fortunaPrng = FortunaRandom()
  ..seed(KeyParameter(Uint8List.fromList(List<int>.generate(
    32,
    (_) => _rand.nextInt(256),
  ))));

/// Makes a [count] byte [Uint8List] random buffer
Uint8List makeRandom(int count) => fortunaPrng.nextBytes(count);

/// Fills an existing [Uint8List] with random bytes.
void fillRandom(Uint8List list) => list.setAll(0, makeRandom(list.length));
