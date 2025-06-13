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

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public class IamTotpMfaEncryptionAndDecryptionHelper {

  public enum AesCipherModes {
    CBC("AES/CBC/PKCS5Padding"),
    GCM("AES/GCM/NoPadding");

    private final String cipherMode;

    AesCipherModes(String cipherMode) {
      this.cipherMode = cipherMode;
    }

    public String getCipherMode() {
      return cipherMode;
    }
  }

  private String encryptionAlgorithm = "AES";
  private AesCipherModes shortFormOfCipherMode = AesCipherModes.GCM;
  private String modeOfOperation = shortFormOfCipherMode.getCipherMode();

  // AES `keySize` has 3 options: 128, 192, or 256 bits.
  private int keyLengthInBits = 128;

  private int ivLengthInBytes = 16;
  private int tagLengthInBits = 128;
  private int ivLengthInBytesForGCM = 12;

  // Multiples of 8
  private int saltLengthInBytes = 16;

  // The higher value the better
  private int iterations = 65536;
  private Charset utf8 = StandardCharsets.UTF_8;

  private static IamTotpMfaEncryptionAndDecryptionHelper instance;

  private IamTotpMfaEncryptionAndDecryptionHelper() {
    // Prevent instantiation
  }

  public String getEncryptionAlgorithm() {
    return encryptionAlgorithm;
  }

  public void setEncryptionAlgorithm(String encryptionAlgorithm) {
    this.encryptionAlgorithm = encryptionAlgorithm;
  }

  public String getModeOfOperation() {
    return modeOfOperation;
  }

  public void setModeOfOperation(String modeOfOperation) {
    this.modeOfOperation = modeOfOperation;
  }

  public int getKeyLengthInBits() {
    return keyLengthInBits;
  }

  public void setKeyLengthInBits(int keyLengthInBits) {
    this.keyLengthInBits = keyLengthInBits;
  }

  public int getIvLengthInBytes() {
    return ivLengthInBytes;
  }

  public void setIvLengthInBytes(int ivLengthInBytes) {
    this.ivLengthInBytes = ivLengthInBytes;
  }

  public int getTagLengthInBits() {
    return tagLengthInBits;
  }

  public void setTagLengthInBits(int tagLengthInBits) {
    this.tagLengthInBits = tagLengthInBits;
  }

  public int getIvLengthInBytesForGCM() {
    return ivLengthInBytesForGCM;
  }

  public void setIvLengthInBytesForGCM(int ivLengthInBytesForGCM) {
    this.ivLengthInBytesForGCM = ivLengthInBytesForGCM;
  }

  public int getSaltLengthInBytes() {
    return saltLengthInBytes;
  }

  public void setSaltLengthInBytes(int saltLengthInBytes) {
    this.saltLengthInBytes = saltLengthInBytes;
  }

  public int getIterations() {
    return iterations;
  }

  public void setIterations(int iterations) {
    this.iterations = iterations;
  }

  public Charset getUtf8() {
    return utf8;
  }

  public AesCipherModes getShortFormOfCipherMode() {
    return shortFormOfCipherMode;
  }

  public void setShortFormOfCipherMode(AesCipherModes shortFormOfCipherMode) {
    this.shortFormOfCipherMode = shortFormOfCipherMode;
  }

  /**
   * Helper to get the instance instead of creating new objects,
   * acts like a singleton pattern.
   */
  public static synchronized IamTotpMfaEncryptionAndDecryptionHelper getInstance() {
    if (instance == null) {
      instance = new IamTotpMfaEncryptionAndDecryptionHelper();
    }

    return instance;
  }
}
