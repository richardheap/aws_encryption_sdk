/// Represents an AWS ARN
///
/// Typical example: arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f
class Arn {
  Arn._(
    this.partition,
    this.service,
    this.region,
    this.account,
    this.resource,
  );

  /// Constructs an ARN by parsing its string representation
  factory Arn.fromString(String arn) {
    final parts = arn.split(':');
    if (parts.length != 6) {
      throw FormatException('Invalid ARN parts');
    }
    if (parts[0] != 'arn') {
      throw FormatException('ARN does not start with arn:');
    }
    if (parts.any((e) => e.isEmpty)) {
      throw FormatException('ARN has an empty part');
    }
    return Arn._(parts[1], parts[2], parts[3], parts[4], parts[5]);
  }

  final String partition;
  final String service;
  final String region;
  final String account;
  final String resource;
}
