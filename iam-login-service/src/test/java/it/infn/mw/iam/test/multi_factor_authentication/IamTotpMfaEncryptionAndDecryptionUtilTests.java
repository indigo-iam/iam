package it.infn.mw.iam.test.multi_factor_authentication;

import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

import it.infn.mw.iam.util.mfa.IamTotpMfaEncryptionAndDecryptionUtil;
import it.infn.mw.iam.util.mfa.IamTotpMfaInvalidArgumentError;

@RunWith(MockitoJUnitRunner.class)
public class IamTotpMfaEncryptionAndDecryptionUtilTests extends IamTotpMfaCommons {

  @Test
  public void testEncryptSecretOrRecoveryCode() throws IamTotpMfaInvalidArgumentError {
    // Encrypt the plainText
    String cipherText = IamTotpMfaEncryptionAndDecryptionUtil.encryptSecretOrRecoveryCode(TOTP_MFA_SECRET, DEFAULT_KEY);

    // Decrypt the cipherText
    String plainText = IamTotpMfaEncryptionAndDecryptionUtil.decryptSecretOrRecoveryCode(cipherText, DEFAULT_KEY);

    assertEquals(TOTP_MFA_SECRET, plainText);
  }

  @Test
  public void testEncryptSecretOrRecoveryCodeWithDifferentKey() throws IamTotpMfaInvalidArgumentError {
    // Encrypt the plainText
    String cipherText = IamTotpMfaEncryptionAndDecryptionUtil.encryptSecretOrRecoveryCode(TOTP_MFA_SECRET, DEFAULT_KEY);

    IamTotpMfaInvalidArgumentError thrownException = assertThrows(IamTotpMfaInvalidArgumentError.class, () -> {
      // Decrypt the cipherText with a different key
      IamTotpMfaEncryptionAndDecryptionUtil.decryptSecretOrRecoveryCode(cipherText, "NOT_THE_SAME_KEY");
    });

    assertTrue(thrownException.getMessage().startsWith("Please use the same password"));

    // Decrypt the cipherText with a the key used for encryption.
    String plainText = IamTotpMfaEncryptionAndDecryptionUtil.decryptSecretOrRecoveryCode(cipherText, DEFAULT_KEY);

    assertEquals(TOTP_MFA_SECRET, plainText);
  }

  @Test
  public void testEncryptSecretOrRecoveryCodeWithTamperedCipher() throws IamTotpMfaInvalidArgumentError {
    // Encrypt the plainText
    String cipherText = IamTotpMfaEncryptionAndDecryptionUtil.encryptSecretOrRecoveryCode(TOTP_MFA_SECRET, DEFAULT_KEY);

    String modifyCipher = cipherText.substring(3);
    String tamperedCipher = "iam" + modifyCipher;

    if (!tamperedCipher.substring(0, 3).equals(cipherText.substring(0, 3))) {

      IamTotpMfaInvalidArgumentError thrownException = assertThrows(IamTotpMfaInvalidArgumentError.class, () -> {
        // Decrypt the cipherText with a different key
        IamTotpMfaEncryptionAndDecryptionUtil.decryptSecretOrRecoveryCode(tamperedCipher, DEFAULT_KEY);
      });

      // Always throws an error because we have tampered with cipherText.
      assertTrue(thrownException.getMessage().startsWith("Please use the same password"));
    } else {

      // Decrypt the cipherText with a the key used for encryption.
      String plainText = IamTotpMfaEncryptionAndDecryptionUtil.decryptSecretOrRecoveryCode(cipherText, DEFAULT_KEY);

      assertEquals(TOTP_MFA_SECRET, plainText);
    }
  }

  @Test
  public void testEncryptSecretOrRecoveryCodeWithEmptyPlainText() throws IamTotpMfaInvalidArgumentError {

    IamTotpMfaInvalidArgumentError thrownException = assertThrows(IamTotpMfaInvalidArgumentError.class, () -> {
      // Try to encrypt the empty plainText
      IamTotpMfaEncryptionAndDecryptionUtil.encryptSecretOrRecoveryCode(null, DEFAULT_KEY);
    });

    // Always throws an error because we have passed empty plaintext.
    assertTrue(thrownException.getMessage().startsWith("Please ensure that you provide"));

  }
}
