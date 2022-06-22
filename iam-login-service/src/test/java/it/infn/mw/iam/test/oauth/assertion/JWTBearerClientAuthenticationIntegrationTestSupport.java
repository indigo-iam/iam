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
package it.infn.mw.iam.test.oauth.assertion;

import static java.util.Collections.singletonList;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ResourceLoader;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.core.jwk.IamJWTSigningService;
import it.infn.mw.iam.test.oauth.EndpointsTestUtils;
import it.infn.mw.iam.util.JWKKeystoreLoader;

public class JWTBearerClientAuthenticationIntegrationTestSupport extends EndpointsTestUtils {

  public static final String CLIENT_ID_SECRET_JWT = "jwt-auth-client_secret_jwt";
  public static final String CLIENT_ID_SECRET_JWT_SECRET = "c8e9eed0-e6e4-4a66-b16e-6f37096356a7";
  public static final String TOKEN_ENDPOINT_AUDIENCE = "http://localhost:8080/token";
  public static final String TOKEN_ENDPOINT = "/token";
  public static final String JWT_BEARER_ASSERTION_TYPE =
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

  public static final String TEST_KEYSTORE_LOCATION = "classpath:/client_auth/client-keys.jwk";

  public static final String CLIENT_ID_PRIVATE_KEY_JWT = "jwt-auth-private_key_jwt";

  @Autowired
  ResourceLoader loader;

  public SignedJWT createSymmetricClientAuthToken(String clientId, Instant expirationTime)
      throws JOSEException {

    JWSSigner signer = new MACSigner(CLIENT_ID_SECRET_JWT_SECRET);
    JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject(clientId)
      .issuer(clientId)
      .expirationTime(Date.from(expirationTime))
      .audience(singletonList(TOKEN_ENDPOINT_AUDIENCE))
      .jwtID(UUID.randomUUID().toString())
      .build();

    SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

    signedJWT.sign(signer);

    return signedJWT;
  }

  public JWTSigningAndValidationService loadSignerService()
      throws NoSuchAlgorithmException, InvalidKeySpecException {

    JWKKeystoreLoader keystoreLoader = new JWKKeystoreLoader(loader);

    JWTSigningAndValidationService svc =
        new IamJWTSigningService(keystoreLoader.loadKeystoreFromLocation(TEST_KEYSTORE_LOCATION),
            "rsa1", JWSAlgorithm.RS256.getName());

    return svc;
  }


}
