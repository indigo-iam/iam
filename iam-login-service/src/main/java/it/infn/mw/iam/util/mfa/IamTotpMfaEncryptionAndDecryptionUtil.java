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

  private static final IamTotpMfaEncryptionAndDecryptionHelper model = IamTotpMfaEncryptionAndDecryptionHelper
      .getInstance();

  private IamTotpMfaEncryptionAndDecryptionUtil() {
    // Prevent instantiation
  }

  /**
   * This process requires a password for encrypting the plaintext. Ensure to use
   * the same password for decryption as well.
   *
   * @param modeOfOperation AES mode of operations.
   * @param input           plaintext to encrypt.
   * @param password        Provided by the admin through the environment
   *                        variable.
   * @param iv              Used as an additional input alongside the encryption
   *                        key.
   *
   * @return String If encryption is successful, the cipherText would be returned.
   *
   * @throws IamTotpMfaInvalidArgumentError
   */
  public static String encryptSecretOrRecoveryCode(String modeOfOperation, String input, String password,
      IvParameterSpec iv)
      throws IamTotpMfaInvalidArgumentError {
    byte[] salt = generateSalt();

    try {
      Key key = getKeyFromPassword(password, salt, model.getEncryptionAlgorithm());

      Cipher cipher1 = Cipher.getInstance(modeOfOperation);
      cipher1.init(Cipher.ENCRYPT_MODE, key, iv);

      byte[] ivBytes = cipher1.getIV();
      byte[] cipherText = cipher1.doFinal(input.getBytes());
      byte[] encryptedData = new byte[salt.length + ivBytes.length + cipherText.length];

      // Append salt, IV, and cipherText into `encryptedData`.
      System.arraycopy(salt, 0, encryptedData, 0, salt.length);
      System.arraycopy(iv.getIV(), 0, encryptedData, salt.length, iv.getIV().length);
      System.arraycopy(cipherText, 0, encryptedData, salt.length + iv.getIV().length, cipherText.length);

      return Base64.getEncoder()
          .encodeToString(encryptedData);
    } catch (Exception exp) {
      throw new IamTotpMfaInvalidArgumentError(
          "Please ensure that you either use the same password or set the password", exp);
    }
  }

  /**
   * Helper to decrypt the cipherText. Ensure you use the same password as you did
   * during encryption.
   *
   * @param modeOfOperation AES mode of operations.
   * @param input           plaintext to encrypt.
   * @param password        Provided by the admin through the environment
   *                        variable.
   *
   * @return String Returns plainText which we obtained from the cipherText.
   *
   * @throws IamTotpMfaInvalidArgumentError
   */
  public static String decryptSecretOrRecoveryCode(String modeOfOperation, String cipherText, String password)
      throws IamTotpMfaInvalidArgumentError {

    try {
      byte[] encryptedData = Base64.getDecoder().decode(cipherText);

      // Extract salt, IV, and cipherText from the combined data
      byte[] salt = Arrays.copyOfRange(encryptedData, 0, model.getSaltSize());
      Key key = getKeyFromPassword(password, salt, model.getEncryptionAlgorithm());
      byte[] ivBytes = Arrays.copyOfRange(encryptedData, model.getSaltSize(), model.getSaltSize() + model.getIvSize());
      byte[] extractedCipherText = Arrays.copyOfRange(encryptedData, model.getSaltSize() + model.getIvSize(),
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
  public static IvParameterSpec getIVSecureRandom(String algorithm)
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
    KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, model.getIterations(), model.getKeySize());
    SecretKey secretKey = new SecretKeySpec(factory.generateSecret(spec)
        .getEncoded(), algorithm);

    return secretKey;
  }

  /**
   * Generates a random salt using a secure random generator.
   */
  private static byte[] generateSalt() {
    byte[] salt = new byte[model.getSaltSize()];
    SecureRandom random = new SecureRandom();

    random.nextBytes(salt);

    return salt;
  }
}
