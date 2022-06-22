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
package it.infn.mw.iam.test.rcauth;

import org.mitre.jose.keystore.JWKSetKeyStore;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;

import com.nimbusds.jose.JWSAlgorithm;

import it.infn.mw.iam.test.ext_authn.x509.X509TestSupport;
import it.infn.mw.iam.test.util.oidc.IdTokenBuilder;

public class RCAuthTestSupport extends X509TestSupport {

  public static final String IAM_BASE_URL = "https://iam.example";

  public static final String HTTPS = "https";
  public static final String RCAUTH_HOST = "rcauth.example";

  public static final String CLIENT_ID = "rcauth-client-id";
  public static final String CLIENT_SECRET = "rcauth-client-secret";
  public static final String ISSUER = "https://rcauth.example/oauth2";

  public static final String LOGIN_URL = "http://localhost/login";

  public static final String AUTHORIZATION_URI = "https://rcauth.example/oauth2/authorize";
  public static final String TOKEN_URI = "https://rcauth.example/oauth2/token";
  public static final String GET_CERT_URI = "https://rcauth.example/oauth2/getcert";

  public static final String JWK_URI = "https://rcauth.example/oauth2/jwk";

  public static final String RANDOM_AUTHZ_CODE = "123";
  public static final String RANDOM_ACCESS_TOKEN = "i_am_an_access_token";

  public static final String SUB = "sub-123";

  public static final String CERT_SUBJECT_DN_CLAIM = "cert_subject_dn";

  public static final String DN = "CN=Test User 123456789,O=INDIGO IAM,C=IT";

  public static final String NONCE = "LolaNonce";

  public static final String IAM_ENTITY_ID = "iam-entity-id";
  public static final String CODE_VALUE = "diablocode";


  public static final String APPLICATION_FORM_URLENCODED_UTF8_VALUE =
      MediaType.APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8";

  public static final MediaType APPLICATION_FORM_URLENCODED_UTF8 =
      MediaType.valueOf(APPLICATION_FORM_URLENCODED_UTF8_VALUE);
  protected JWKSetKeyStore rcAuthKeyStore = rcAuthKeyStore();
  protected JWSAlgorithm jwsAlgo = JWSAlgorithm.RS256;

  protected IdTokenBuilder tokenBuilder = new IdTokenBuilder(rcAuthKeyStore, jwsAlgo);

  public JWKSetKeyStore rcAuthKeyStore() {
    JWKSetKeyStore ks = new JWKSetKeyStore();
    ks.setLocation(new ClassPathResource("/oidc/mock_op_keys.jks"));
    return ks;
  }

}
