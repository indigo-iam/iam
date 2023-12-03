/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package it.infn.mw.iam.util.mfa;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;

public class IamTotpMfaEncryptionAndDecryptionUtil {

  private static final IamTotpMfaEncryptionAndDecryptionHelper defaultModel = IamTotpMfaEncryptionAndDecryptionHelper
      .getInstance();

  private IamTotpMfaEncryptionAndDecryptionUtil() {
  }

  /**
   * This process requires a password for encrypting the plaintext. Ensure to use
   * the same password for decryption as well.
   *
   * @param plaintext plaintext to encrypt.
   * @param password  Provided by the admin through the environment
   *                  variable.
   *
   * @return String If encryption is successful, the cipherText would be returned.
   *
   * @throws IamTotpMfaInvalidArgumentError
   */
  public static String encryptSecretOrRecoveryCode(String plaintext, String password)
      throws IamTotpMfaInvalidArgumentError {
    byte[] salt = generateSalt();
    String modeOfOperation = defaultModel.getModeOfOperation();

    if (validatePlaintext(plaintext) || validatePlaintext(password)) {
      throw new IamTotpMfaInvalidArgumentError(
          "Please ensure that you provide plaintext and the password");
    }

    try {
      Key key = getKeyFromPassword(password, salt, defaultModel.getEncryptionAlgorithm());
      IvParameterSpec iv = getIVSecureRandom(defaultModel.getModeOfOperation());

      Cipher cipher1 = Cipher.getInstance(modeOfOperation);
      cipher1.init(Cipher.ENCRYPT_MODE, key, iv);

      byte[] ivBytes = cipher1.getIV();
      byte[] cipherText = cipher1.doFinal(plaintext.getBytes());
      byte[] encryptedData = new byte[salt.length + ivBytes.length + cipherText.length];

      // Append salt, IV, and cipherText into `encryptedData`.
      System.arraycopy(salt, 0, encryptedData, 0, salt.length);
      System.arraycopy(iv.getIV(), 0, encryptedData, salt.length, iv.getIV().length);
      System.arraycopy(cipherText, 0, encryptedData, salt.length + iv.getIV().length, cipherText.length);

      return Base64.getEncoder()
          .encodeToString(encryptedData);
    } catch (Exception exp) {
      throw new IamTotpMfaInvalidArgumentError(
          "Please ensure that you provide plaintext and the password", exp);
    }
  }

  /**
   * Helper to decrypt the cipherText. Ensure you use the same password as you did
   * during encryption.
   *
   * @param cipherText Encrypted data which help us to extract the plaintext.
   * @param password   Provided by the admin through the environment
   *                   variable.
   *
   * @return String Returns plainText which we obtained from the cipherText.
   *
   * @throws IamTotpMfaInvalidArgumentError
   */
  public static String decryptSecretOrRecoveryCode(String cipherText, String password)
      throws IamTotpMfaInvalidArgumentError {
    String modeOfOperation = defaultModel.getModeOfOperation();

    if (validatePlaintext(cipherText) || validatePlaintext(password)) {
      throw new IamTotpMfaInvalidArgumentError(
          "Please ensure that you provide cipherText and the password");
    }

    try {
      byte[] encryptedData = Base64.getDecoder().decode(cipherText);

      // Extract salt, IV, and cipherText from the combined data
      byte[] salt = Arrays.copyOfRange(encryptedData, 0, defaultModel.getSaltSize());
      Key key = getKeyFromPassword(password, salt, defaultModel.getEncryptionAlgorithm());
      byte[] ivBytes = Arrays.copyOfRange(encryptedData, defaultModel.getSaltSize(),
          defaultModel.getSaltSize() + defaultModel.getIvSize());
      byte[] extractedCipherText = Arrays.copyOfRange(encryptedData,
          defaultModel.getSaltSize() + defaultModel.getIvSize(),
          encryptedData.length);

      Cipher cipher = Cipher.getInstance(modeOfOperation);

      cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivBytes));

      byte[] decryptedTextBytes = cipher.doFinal(
          Base64.getDecoder().decode(
              Base64.getEncoder().encodeToString(extractedCipherText)));

      return new String(decryptedTextBytes);
    } catch (Exception exp) {
      throw new IamTotpMfaInvalidArgumentError(
          "Please use the same password and mode of operation which you used for encryption");
    }
  }

  /**
   * Generates a random Initialization Vector(IV) using a secure random generator.
   *
   * @param algorithm A symmetric key algorithm (AES) has been used.
   *
   * @return IvParameterSpec
   *
   * @throws NoSuchAlgorithmException
   * @throws NoSuchPaddingException
   */
  private static IvParameterSpec getIVSecureRandom(String algorithm)
      throws NoSuchAlgorithmException, NoSuchPaddingException {
    SecureRandom random = SecureRandom.getInstanceStrong();
    byte[] iv = new byte[Cipher.getInstance(algorithm).getBlockSize()];

    random.nextBytes(iv);

    return new IvParameterSpec(iv);
  }

  /**
   * Generates the key which can be used to encrypt and decrypt the plaintext.
   *
   * @param password  Provided by the admin through the environment
   *                  variable.
   * @param salt      Ensures derived keys to be different.
   * @param algorithm A symmetric key algorithm (AES) has been used.
   *
   * @return SecretKey
   *
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeySpecException
   */
  private static SecretKey getKeyFromPassword(String password, byte[] salt, String algorithm)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, defaultModel.getIterations(),
        defaultModel.getKeySize());
    SecretKey secretKey = new SecretKeySpec(factory.generateSecret(spec)
        .getEncoded(), algorithm);

    return secretKey;
  }

  /**
   * Generates a random salt using a secure random generator.
   */
  private static byte[] generateSalt() {
    byte[] salt = new byte[defaultModel.getSaltSize()];
    SecureRandom random = new SecureRandom();

    random.nextBytes(salt);

    return salt;
  }

  private static boolean validatePlaintext(String text) {
    return (text == null || text.isEmpty());
  }
}
