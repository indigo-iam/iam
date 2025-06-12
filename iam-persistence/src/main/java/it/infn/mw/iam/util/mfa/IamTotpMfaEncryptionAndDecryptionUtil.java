/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2025
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
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.nio.ByteBuffer;

public class IamTotpMfaEncryptionAndDecryptionUtil {

  private static final IamTotpMfaEncryptionAndDecryptionHelper defaultModel = IamTotpMfaEncryptionAndDecryptionHelper
      .getInstance();

  private IamTotpMfaEncryptionAndDecryptionUtil() {
  }

  /**
   * This helper method requires a password for encrypting the plaintext.
   * Ensure to use the same password for decryption as well.
   *
   * @param plaintext plaintext to encrypt.
   * @param password  Provided by the admin through the environment
   *                  variable.
   *
   * @return String If encryption is successful, the cipherText would be returned.
   *
   * @throws IamTotpMfaInvalidArgumentError
   */
  public static String encryptSecret(String plaintext, String password)
      throws IamTotpMfaInvalidArgumentError {
    String modeOfOperation = defaultModel.getModeOfOperation();

    if (validateText(plaintext) || validateText(password)) {
      throw new IamTotpMfaInvalidArgumentError(
          "Please ensure that you provide plaintext and the password");
    }

    try {
      byte[] salt = generateNonce(defaultModel.getSaltLengthInBytes());
      Key key = getKeyFromPassword(password, salt, defaultModel.getEncryptionAlgorithm());
      byte[] iv;

      Cipher cipher = Cipher.getInstance(modeOfOperation);

      if (isCipherModeCBC()) {
        IvParameterSpec ivParamSpec = getIVSecureRandom(defaultModel.getIvLengthInBytes());

        cipher.init(Cipher.ENCRYPT_MODE, key, ivParamSpec);

        iv = cipher.getIV();
      } else {
        iv = generateNonce(defaultModel.getIvLengthInBytesForGCM());

        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(defaultModel.getTagLengthInBits(), iv));
      }

      byte[] cipherText = cipher.doFinal(plaintext.getBytes());

      // Append salt, IV, and cipherText into `encryptedData`.
      byte[] encryptedData = ByteBuffer.allocate(salt.length + iv.length + cipherText.length)
          .put(salt)
          .put(iv)
          .put(cipherText)
          .array();

      return Base64.getEncoder()
          .encodeToString(encryptedData);
    } catch (Exception exp) {
      throw new IamTotpMfaInvalidArgumentError(
          "An error occurred while encrypting secret", exp);
    }
  }

  /**
   * Helper to decrypt the cipherText. Ensure you use the same password as you did
   * during encryption.
   *
   * @param cText    Encrypted data which help us to extract the plaintext.
   * @param password Provided by the admin through the environment
   *                 variable.
   *
   * @return String Returns plainText which we obtained from the cipherText.
   *
   * @throws IamTotpMfaInvalidArgumentError
   */
  public static String decryptSecret(String cText, String password)
      throws IamTotpMfaInvalidArgumentError {
    String modeOfOperation = defaultModel.getModeOfOperation();

    if (validateText(cText) || validateText(password)) {
      throw new IamTotpMfaInvalidArgumentError(
          "Please ensure that you provide cipherText and the password");
    }

    try {
      byte[] encryptedData = Base64.getDecoder().decode(cText);

      ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedData);

      // Extract salt, IV, and cipherText from the combined data
      byte[] salt = new byte[defaultModel.getSaltLengthInBytes()];
      byteBuffer.get(salt);

      byte[] iv;

      if (isCipherModeCBC()) {
        iv = new byte[defaultModel.getIvLengthInBytes()];
      } else {
        iv = new byte[defaultModel.getIvLengthInBytesForGCM()];
      }

      byteBuffer.get(iv);

      byte[] cipherText = new byte[byteBuffer.remaining()];
      byteBuffer.get(cipherText);

      Key key = getKeyFromPassword(password, salt, defaultModel.getEncryptionAlgorithm());

      Cipher cipher = Cipher.getInstance(modeOfOperation);

      if (isCipherModeCBC()) {
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
      } else {
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(defaultModel.getTagLengthInBits(), iv));
      }

      byte[] decryptedTextBytes = cipher.doFinal(cipherText);

      return new String(decryptedTextBytes);
    } catch (Exception exp) {
      throw new IamTotpMfaInvalidArgumentError(
          "An error occurred while decrypting ciphertext", exp);
    }
  }

  /**
   * Generates a random Initialization Vector(IV) using a secure random generator.
   *
   * @param byteSize. Specifies IV length for CBC.
   *
   * @return IvParameterSpec
   *
   * @throws NoSuchAlgorithmException
   */
  private static IvParameterSpec getIVSecureRandom(int byteSize)
      throws NoSuchAlgorithmException {
    SecureRandom random = SecureRandom.getInstanceStrong();
    byte[] iv = new byte[byteSize];

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
        defaultModel.getKeyLengthInBits());

    byte[] calculatedHash = factory.generateSecret(spec).getEncoded();
    byte[] storedHash = factory.generateSecret(spec).getEncoded();

    if (MessageDigest.isEqual(calculatedHash, storedHash)) {
      return new SecretKeySpec(calculatedHash, algorithm);
    } else {
      throw new IamTotpMfaInvalidArgumentError("Invalid password");
    }
  }

  /**
   * Generates a random salt using a secure random generator.
   *
   * @param byteSize Specifies either salt or IV for GCM byte length
   *
   * @return byte[]
   * @throws NoSuchAlgorithmException
   */
  private static byte[] generateNonce(int byteSize) throws NoSuchAlgorithmException {
    SecureRandom random = SecureRandom.getInstanceStrong();
    byte[] salt = new byte[byteSize];

    random.nextBytes(salt);

    return salt;
  }

  /**
   * Helper method to determine whether the provided text is an empty or NULL.
   *
   * @return boolean
   */
  private static boolean validateText(String text) {
    return (text == null || text.isEmpty());
  }

  /**
   * Helper method to determine whether it is in CBC mode or NOT.
   *
   * @return boolean
   */
  private static boolean isCipherModeCBC() {
    return defaultModel.getModeOfOperation().equalsIgnoreCase(
        IamTotpMfaEncryptionAndDecryptionHelper.AesCipherModes.CBC.getCipherMode());
  }
}
