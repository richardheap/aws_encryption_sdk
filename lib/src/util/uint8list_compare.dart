import 'dart:math';
import 'dart:typed_data';

int unsignedByteListCompare(Uint8List a, Uint8List b) {
  final minLength = min(a.length, b.length);
  for (var i = 0; i < minLength; i++) {
    // NB no need to zero extend (e.g. & 0xff) as this is a Uint8List (unsigned)
    var result = a[i].compareTo(b[i]);
    if (result != 0) {
      return result;
    }
  }
  return a.length - b.length;
}

bool unsignedByteListEquals(Uint8List a, Uint8List b) =>
    unsignedByteListCompare(a, b) == 0;

bool prefixCompare(Uint8List a, Uint8List b) {
  final minLength = min(a.length, b.length);
  // make it constant
  var delta = 0;
  for (var i = 0; i < minLength; i++) {
    delta |= a[i] ^ b[i];
  }
  return delta == 0;
}
