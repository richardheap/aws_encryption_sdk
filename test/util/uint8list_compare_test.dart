import 'dart:collection';
import 'dart:typed_data';

import 'package:aws_encryption_sdk/src/util/uint8list_compare.dart';
import 'package:test/test.dart';

void main() {
  final a = Uint8List.fromList([0, 1, 2]); // second smallest
  final b = Uint8List.fromList([0, 1, 1]); // smallest
  final c1 = Uint8List.fromList([1, 1, 1]); // third smallest
  final c2 = Uint8List.fromList([1, 1, 1]);
  final d = Uint8List.fromList([1, 1, 1, 0]); // 2nd largest
  final e = Uint8List.fromList([1, 1, 1, 255]); // largest - beware 'negative'

  group('Test comparator', () {
    test('pairwise comparisons are correct', () {
      expect(unsignedByteListCompare(a, b), 1);
      expect(unsignedByteListCompare(a, c1), -1);
      expect(unsignedByteListCompare(c1, a), 1);
      expect(unsignedByteListCompare(c1, c2), 0);
      expect(unsignedByteListCompare(c1, d), -1);
      expect(unsignedByteListCompare(d, e), -1);
    });

    test('works as a map key comparator', () {
      final map = SplayTreeMap<Uint8List, String>(unsignedByteListCompare);
      map[a] = 'a';
      map[b] = 'b';
      map[c1] = 'c';
      map[d] = 'd';
      map[e] = 'e';

      expect(map.values.toList(), <String>['b', 'a', 'c', 'd', 'e']);
    });

    test('convenience equals works', (){
      expect(unsignedByteListEquals(c1, c2), isTrue);
      expect(unsignedByteListEquals(a, b), isFalse);
    });
  });

  group('Test prefix equality', () {
    test('detects equals', () {
      expect(prefixCompare(c1, c2), true);
      expect(prefixCompare(c1, d), true);
      expect(prefixCompare(d, c1), true);
    });

    test('detects unequal', () {
      expect(prefixCompare(a, b), false);
      expect(prefixCompare(a, c1), false);
    });
  });
}
