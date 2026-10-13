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
package it.infn.mw.iam.api.account.multi_factor_authentication.passkey;

import java.io.Serializable;
import java.time.Instant;
import java.util.Arrays;

/**
 * A WebAuthn challenge issued to a user and kept in the HTTP session between the options request
 * and the completion of a ceremony. The challenge is bound to a purpose and to the account it was
 * issued for, is single use, and expires
 */
public class PasskeyChallenge implements Serializable {

  private static final long serialVersionUID = 1L;

  public static final String SESSION_ATTRIBUTE = "iam.passkey.challenge";

  public enum Purpose {
    /** navigator.credentials.create(), to register a new passkey */
    REGISTRATION,
    /** navigator.credentials.get(), to verify the second factor at login */
    AUTHENTICATION,
    /** navigator.credentials.get(), to prove possession of a passkey before removing one */
    REMOVAL;

    public boolean isAssertion() {
      return this != REGISTRATION;
    }
  }

  private final byte[] value;
  private final Purpose purpose;
  private final String username;
  private final long expiresAtEpochMillis;

  public PasskeyChallenge(byte[] value, Purpose purpose, String username, Instant expiresAt) {
    this.value = Arrays.copyOf(value, value.length);
    this.purpose = purpose;
    this.username = username;
    this.expiresAtEpochMillis = expiresAt.toEpochMilli();
  }

  public byte[] getValue() {
    return Arrays.copyOf(value, value.length);
  }

  public Purpose getPurpose() {
    return purpose;
  }

  public String getUsername() {
    return username;
  }

  public Instant getExpiresAt() {
    return Instant.ofEpochMilli(expiresAtEpochMillis);
  }

  public boolean isExpired(Instant now) {
    return !now.isBefore(getExpiresAt());
  }

  public boolean matches(Purpose expectedPurpose, String expectedUsername) {
    return purpose == expectedPurpose && username.equals(expectedUsername);
  }
}
