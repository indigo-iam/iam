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
package it.infn.mw.iam.test.multi_factor_authentication;

public class IamTotpMfaCommons {
  public static final String KEY_TO_ENCRYPT_DECRYPT = "define_me_please";
  public static final String TOTP_MFA_SECRET = "secret";

  public static final int DEFAULT_KEY_SIZE = 128;
  public static final int DEFAULT_ITERATIONS = 65536;
  public static final int DEFAULT_SALT_SIZE = 16;

  public static final int ANOTHER_KEY_SIZE = 192;
  public static final int ANOTHER_ITERATIONS = 6000;
  public static final int ANOTHER_SALT_SIZE = 8;
}
