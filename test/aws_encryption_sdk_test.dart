import 'end_to_end/aes_stream_test.dart' as e2es;
import 'end_to_end/aes_test.dart' as e2et;
import 'internal/committed_key_test.dart' as ickt;
import 'internal/encryption_context_codec_test.dart' as iecct;
import 'internal/gcm_test.dart' as igcmt;
import 'keyring/aes_keyring_test.dart' as aeskt;
import 'keyring/key_cipher_test.dart' as kct;
import 'keyring/rsa_keyring_test.dart' as rsakt;
import 'util/arn_test.dart' as uat;
import 'util/uint8list_compare_test.dart' as uuct;

void main() {
  e2et.main();
  e2es.main();
  ickt.main();
  iecct.main();
  igcmt.main();
  aeskt.main();
  rsakt.main();
  kct.main();
  uat.main();
  uuct.main();
}
