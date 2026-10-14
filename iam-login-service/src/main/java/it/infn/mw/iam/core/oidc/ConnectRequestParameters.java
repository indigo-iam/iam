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
package it.infn.mw.iam.core.oidc;

public final class ConnectRequestParameters {

  public static final String CLIENT_ID = "client_id";
  public static final String REDIRECT_URI = "redirect_uri";
  public static final String STATE = "state";
  public static final String REQUEST = "request";
  public static final String LOGIN_HINT = "login_hint";
  public static final String MAX_AGE = "max_age";
  public static final String CLAIMS = "claims";
  public static final String SCOPE = "scope";
  public static final String NONCE = "nonce";
  public static final String PROMPT = "prompt";

  // prompt values
  public static final String PROMPTED = "PROMPT_FILTER_PROMPTED";
  public static final String PROMPT_REQUESTED = "PROMPT_FILTER_REQUESTED";
  public static final String PROMPT_LOGIN = "login";
  public static final String PROMPT_NONE = "none";
  public static final String PROMPT_CONSENT = "consent";
  public static final String PROMPT_SEPARATOR = " ";

  // extensions
  public static final String APPROVED_SITE = "approved_site";

  // responses
  public static final String ERROR = "error";
  public static final String LOGIN_REQUIRED = "login_required";

  // audience
  public static final String AUD = "aud";

  // PKCE
  public static final String CODE_CHALLENGE = "code_challenge";
  public static final String CODE_CHALLENGE_METHOD = "code_challenge_method";
  public static final String CODE_VERIFIER = "code_verifier";

  private ConnectRequestParameters() {}

}
