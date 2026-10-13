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
package it.infn.mw.iam.authn.multi_factor_authentication;

import java.util.Collections;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;

import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyChallenge;

/**
 * Carries a pre-authenticated user through passkey verification. Wraps the pre-authenticated
 * token, the WebAuthn assertion produced by the browser and the challenge issued for it, so that
 * {@link MultiFactorPasskeyCheckProvider} can verify the assertion and upgrade the wrapped token to
 * a full authentication
 */
public class PasskeyAssertionAuthenticationToken extends AbstractAuthenticationToken {

  private static final long serialVersionUID = 1L;

  private final transient Authentication preAuthentication;
  private final String assertion;
  private final PasskeyChallenge challenge;

  public PasskeyAssertionAuthenticationToken(Authentication preAuthentication, String assertion,
      PasskeyChallenge challenge) {
    super(Collections.emptyList());
    this.preAuthentication = preAuthentication;
    this.assertion = assertion;
    this.challenge = challenge;
    setAuthenticated(false);
  }

  public Authentication getPreAuthentication() {
    return preAuthentication;
  }

  public String getAssertion() {
    return assertion;
  }

  public PasskeyChallenge getChallenge() {
    return challenge;
  }

  @Override
  public Object getCredentials() {
    return assertion;
  }

  @Override
  public Object getPrincipal() {
    return preAuthentication.getPrincipal();
  }

  @Override
  public String getName() {
    return preAuthentication.getName();
  }
}
