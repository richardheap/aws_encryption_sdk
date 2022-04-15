class AwsCryptoException implements Exception {
  AwsCryptoException(this.msg);

  final String msg;

  @override
  String toString() => 'AwsCryptoException: $msg';
}

class BadCiphertextException implements AwsCryptoException {
  BadCiphertextException(this.msg);

  @override
  final String msg;

  @override
  String toString() => 'BadCiphertextException: $msg';
}

class ParseException implements AwsCryptoException {
  ParseException(this.msg);

  @override
  final String msg;

  @override
  String toString() => 'ParseException: $msg';
}

class CannotUnwrapDataKeyException implements AwsCryptoException {
  CannotUnwrapDataKeyException(this.msg);

  @override
  final String msg;

  @override
  String toString() => 'CannotUnwrapDataKeyException: $msg';
}