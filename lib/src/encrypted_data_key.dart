import 'dart:typed_data';

abstract class EncryptedDataKey {
  String get providerId;

  String get providerInfoString;

  Uint8List get providerInformation;

  Uint8List get encryptedDataKey;
}
