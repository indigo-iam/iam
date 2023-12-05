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

public class IamTotpMfaEncryptionAndDecryptionHelper {

  private String encryptionAlgorithm = "AES";
  private String modeOfOperation = "AES/CBC/PKCS5Padding";

  // AES `keySize` has 3 options: 128, 192, or 256 bits.
  private int keySize = 128;

  private int ivSize = 16;

  // Multiples of 8
  private int saltSize = 16;

  // The higher value the better
  private int iterations = 65536;

  private static IamTotpMfaEncryptionAndDecryptionHelper instance;

  private IamTotpMfaEncryptionAndDecryptionHelper() {
    // Prevent instantiation
  }

  public int getKeySize() {
    return keySize;
  }

  public void setKeySize(int keySize) {
    this.keySize = keySize;
  }

  public int getIvSize() {
    return ivSize;
  }

  public int getSaltSize() {
    return saltSize;
  }

  public void setSaltSize(int saltSize) {
    this.saltSize = saltSize;
  }

  public int getIterations() {
    return iterations;
  }

  public void setIterations(int iterations) {
    this.iterations = iterations;
  }

  public String getEncryptionAlgorithm() {
    return encryptionAlgorithm;
  }

  public String getModeOfOperation() {
    return modeOfOperation;
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
