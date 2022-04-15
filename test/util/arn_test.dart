import 'package:aws_encryption_sdk/src/util/arn.dart';
import 'package:test/test.dart';

void main() {
  group('ARN parser tests', () {
    test('can parse', () {
      final arn = Arn.fromString(
        'arn:aws:kms:us-west-2:658956600833:'
        'key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f',
      );
      expect(arn.partition, 'aws');
      expect(arn.service, 'kms');
      expect(arn.region, 'us-west-2');
      expect(arn.account, '658956600833');
      expect(arn.resource, 'key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f');
    });

    test('detects wrong parts', () {
      expect(
        () => Arn.fromString(
          'arn:kms:us-west-2:658956600833:'
          'key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f',
        ),
        throwsFormatException,
      );
    });

    test('detects wrong prefix', () {
      expect(
        () => Arn.fromString(
          'arp:aws:kms:us-west-2:658956600833:'
          'key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f',
        ),
        throwsFormatException,
      );
    });

    test('detects empty part', () {
      expect(
        () => Arn.fromString(
          'arn::kms:us-west-2:658956600833:'
          'key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f',
        ),
        throwsFormatException,
      );
    });
  });
}
