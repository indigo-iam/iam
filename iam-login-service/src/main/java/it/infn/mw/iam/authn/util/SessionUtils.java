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
package it.infn.mw.iam.authn.util;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.text.ParseException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.security.authentication.AuthenticationServiceException;

import com.google.common.base.Strings;
import com.nimbusds.jwt.JWTClaimsSet;

public class SessionUtils {

  public static final String CODE_VERIFIER_SESSION_VARIABLE = "code_verifier";
  public static final String STATE_SESSION_VARIABLE = "state";
  public static final String NONCE_SESSION_VARIABLE = "nonce";

  /**
   * Get the named stored session variable as a string. Return null if not found or not a string.
   *
   * @param session the session
   *
   * @param key the key
   *
   * @return the named stored session variable
   */
  public static String getStoredSessionString(HttpSession session, String key) {

    Object o = session.getAttribute(key);
    if (o != null && o instanceof String) {
      return (String) o;
    } else {
      return null;
    }
  }

  public static void validateState(HttpServletRequest request) {

    HttpSession session = request.getSession();

    String storedState = getStoredState(session);
    String requestState = request.getParameter(STATE_SESSION_VARIABLE);

    if (storedState == null || !storedState.equals(requestState)) {
      throw new AuthenticationServiceException(String.format(
          "State parameter mismatch on return. Expected %s got %s", storedState, requestState));
    }
  }

  public static void validateNonceSession(HttpSession session, JWTClaimsSet idClaims) {
    String nonce;
    try {
      nonce = idClaims.getStringClaim(NONCE_SESSION_VARIABLE);
    } catch (ParseException e) {
      throw new AuthenticationServiceException(
          String.format("nonce claim parse error: %s", e.getMessage()));
    }

    if (Strings.isNullOrEmpty(nonce)) {
      throw new AuthenticationServiceException("ID token did not contain a nonce claim.");
    }

    String storedNonce = getStoredNonce(session);

    if (!nonce.equals(storedNonce)) {
      throw new AuthenticationServiceException(String.format(
          "Possible replay attack detected! The comparison of the nonce in the returned "
              + "ID Token to the session %s failed. Expected %s got %s.",
          NONCE_SESSION_VARIABLE, storedNonce, nonce));
    }
  }

  public static String createNonce(HttpSession session) {
    String nonce = new BigInteger(50, new SecureRandom()).toString(16);
    session.setAttribute(NONCE_SESSION_VARIABLE, nonce);

    return nonce;
  }

  public static String createState(HttpSession session) {
    String state = new BigInteger(50, new SecureRandom()).toString(16);
    session.setAttribute(STATE_SESSION_VARIABLE, state);

    return state;
  }

  public static String createCodeVerifier(HttpSession session) {
    String challenge = new BigInteger(50, new SecureRandom()).toString(16);
    session.setAttribute(CODE_VERIFIER_SESSION_VARIABLE, challenge);
    return challenge;
  }

  public static String getStoredState(HttpSession session) {
    return getStoredSessionString(session, STATE_SESSION_VARIABLE);
  }

  public static String getStoredNonce(HttpSession session) {
    return getStoredSessionString(session, NONCE_SESSION_VARIABLE);
  }

  public static String getStoredCodeVerifier(HttpSession session) {
    return getStoredSessionString(session, CODE_VERIFIER_SESSION_VARIABLE);
  }

}
