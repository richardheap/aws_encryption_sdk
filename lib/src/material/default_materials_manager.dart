import '../crypto_algorithm.dart';
import '../encrypted_data_key.dart';
import '../exception/exceptions.dart';
import '../internal/constants.dart';
import '../internal/trailing_signature_algorithm.dart';
import '../keyring/keyring.dart';
import 'cryptographic_material.dart';

abstract class MaterialsManager {
  MaterialsManager(this._keyring);

  final Keyring _keyring;

  Future<EncryptionMaterials> getEncryptionMaterials(
    CryptoAlgorithm cryptoAlgorithm,
    Map<String, String> encryptionContext,
  );

  Future<DecryptionMaterials> decryptMaterials(
    CryptoAlgorithm cryptoAlgorithm,
    Map<String, String> encryptionContext,
    List<EncryptedDataKey> edks,
    TrailingSignatureAlgorithm? trailingSignatureAlgorithm,
  );
}

class DefaultMaterialsManager extends MaterialsManager {
  DefaultMaterialsManager(super.keyring);

  //This operation will add a key-value pair to the encryption context included in the request using the key aws-crypto-public-key. If the encryption context included in the request already contains the aws-crypto-public-key key, this operation MUST fail rather than overwrite the associated value.
  //
  // If the encryption materials request does not contain an algorithm suite, the algorithm suite with algorithm suite ID 03 78 (hex) MUST be added as the algorithm suite in the encryption materials returned.
  // If the encryption materials request does contain an algorithm suite, the encryption materials returned MUST contain the same algorithm suite.
  // If the algorithm suite contains a signing algorithm, the default CMM MUST:
  //
  // Generate a signing key
  // Add the following key-value pair to the encryption context:
  // The key MUST be the reserved name, aws-crypto-public-key.
  // The value MUST be the base64-encoded public verification key.
  // On each call to Get Encryption Materials, the default CMM MUST make a call to its keyring's On Encrypt operation.
  //
  // The default CMM MUST obtain the following from the response:
  //
  // Plaintext Data Key
  // Encrypted Data Keys
  // The values obtained above MUST be included in the encryption materials returned.

  @override
  Future<DecryptionMaterials> decryptMaterials(
    CryptoAlgorithm cryptoAlgorithm,
    Map<String, String> encryptionContext,
    List<EncryptedDataKey> edks,
    TrailingSignatureAlgorithm? trailingSignatureAlgorithm,
  ) async {
    // If the algorithm suite contains a signing algorithm, the default CMM MUST remove the verification key from the encryption context.
    //
    // On each call to Decrypt Materials, the default CMM MUST make a call to its keyring's On Decrypt operation.
    //
    // The default CMM MUST obtain the following from the response:
    //
    // Plaintext Data Key
    // The values obtained above MUST be included in the decrypt materials returned.

    final plaintextKey = await _keyring.onDecrypt(
      cryptoAlgorithm,
      edks,
      encryptionContext,
    );

    if (cryptoAlgorithm.trailingSignatureLength > 0) {
      final serializedPubKey = encryptionContext[ecPublicKeyField];
      if (serializedPubKey == null) {
        throw AwsCryptoException('Missing trailing signature public key');
      }

      if (trailingSignatureAlgorithm == null) {
        throw AwsCryptoException('Trailing signature was not created');
      }

      try {
        trailingSignatureAlgorithm.deserializePublicKey(serializedPubKey);
      } catch (e) {
        throw AwsCryptoException(e.toString());
      }
      encryptionContext.remove(ecPublicKeyField);
    } else if (encryptionContext.containsKey(ecPublicKeyField)) {
      throw AwsCryptoException(
        'Trailing signature public key found for non-signed algorithm',
      );
    }

    return DecryptionMaterials(plaintextKey, trailingSignatureAlgorithm);
  }

  @override
  Future<EncryptionMaterials> getEncryptionMaterials(
    CryptoAlgorithm cryptoAlgorithm,
    Map<String, String> encryptionContext,
  ) async {
    //AsymmetricKeyPair<PublicKey, PrivateKey>? trailingKeypair;
    TrailingSignatureAlgorithm? trailingSignatureAlgorithm;
    if (cryptoAlgorithm.trailingSignatureLength > 0) {
      trailingSignatureAlgorithm =
          TrailingSignatureAlgorithm.fromAlgorithm(cryptoAlgorithm);
      trailingSignatureAlgorithm.generateKey();
      if (encryptionContext.containsKey(ecPublicKeyField)) {
        throw AwsCryptoException(
          'EncryptionContext contains reserved field $ecPublicKeyField',
        );
      }
      encryptionContext = Map.from(encryptionContext);
      encryptionContext[ecPublicKeyField] =
          trailingSignatureAlgorithm.serializePublicKey();
    }

    final materials = EncryptionMaterials(
      cryptoAlgorithm,
      encryptionContext,
      trailingSignatureAlgorithm,
    );

    await _keyring.onEncrypt(materials);

    return materials;
  }
}
