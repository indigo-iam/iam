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

import static org.mockito.Mockito.when;

import java.util.function.Consumer;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.ClientDetailsEntity.AuthMethod;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public interface IAMJWTBearerAuthenticationProviderTestSupport {

  String JWT_AUTH_NAME = "jwt-bearer-client";
  String ISSUER = "http://localhost:8080/";
  String ISSUER_NO_TRAILING_SLASH = "http://localhost:8080/";

  String ISSUER_TOKEN_ENDPOINT = "http://localhost:8080/token";

  String CLIENT_SECRET = "bf4a39e1-43df-4e6f-b9b8-9a359108ac91";

  JWSHeader JWS_HEADER_HS256 = new JWSHeader(JWSAlgorithm.HS256);

  JWTClaimsSet JUST_SUB_JWT = new JWTClaimsSet.Builder().subject("jwt-bearer-client").build();


  GrantedAuthority ROLE_CLIENT_AUTHORITY = new SimpleGrantedAuthority("ROLE_CLIENT");

  default SignedJWT macSignJwt(JWTClaimsSet claimSet) throws JOSEException {

    SignedJWT jws = new SignedJWT(JWS_HEADER_HS256, claimSet);
    MACSigner signer = new MACSigner(CLIENT_SECRET);

    jws.sign(signer);
    return jws;

  }

  default void testForAllAlgos(ClientDetailsEntity client,
      Consumer<JWSAlgorithm> test) {
    
    when(client.getTokenEndpointAuthMethod()).thenReturn(AuthMethod.SECRET_JWT);
    JWSAlgorithm.Family.HMAC_SHA.forEach(test);
    when(client.getTokenEndpointAuthMethod()).thenReturn(AuthMethod.PRIVATE_KEY);
    JWSAlgorithm.Family.SIGNATURE.forEach(test);
  }




}
