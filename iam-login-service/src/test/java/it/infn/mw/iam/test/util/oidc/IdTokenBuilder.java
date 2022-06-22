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
package it.infn.mw.iam.test.util.oidc;

import static com.google.common.collect.Maps.newHashMap;

import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.mitre.jose.keystore.JWKSetKeyStore;

import com.google.common.base.Strings;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class IdTokenBuilder {

  String issuer;
  String sub;

  Date issueTime;
  Date expirationTime;

  List<String> audience;

  String jwtId;
  String nonce;

  final JWKSetKeyStore keyStore;
  final JWSAlgorithm signingAlgo;
  JWSSigner signer;
  
  Map<String, String> customClaims = newHashMap();

  public IdTokenBuilder(JWKSetKeyStore keyStore, JWSAlgorithm algo) {
    Calendar cal = Calendar.getInstance();
    issueTime = cal.getTime();
    cal.add(Calendar.HOUR, 1);
    expirationTime = cal.getTime();
    jwtId = UUID.randomUUID().toString();
    this.keyStore = keyStore;
    this.signingAlgo = algo;

    for (JWK key : keyStore.getKeys()) {
      if (key instanceof RSAKey && key.isPrivate()) {
	try {
	  signer = new RSASSASigner((RSAKey) key);
	} catch (JOSEException e) {
	  throw new RuntimeException(e);
	}
      }
    }
  }


  public IdTokenBuilder issuer(String issuer) {
    this.issuer = issuer;
    return this;
  }

  public IdTokenBuilder sub(String sub) {
    this.sub = sub;
    return this;
  }

  public IdTokenBuilder issueTime(Date issueTime) {
    this.issueTime = issueTime;
    return this;
  }

  public IdTokenBuilder expirationTime(Date expirationTime) {
    this.expirationTime = expirationTime;
    return this;
  }

  public IdTokenBuilder audience(String... aud) {
    this.audience = Arrays.asList(aud);
    return this;
  }

  public IdTokenBuilder nonce(String nonce) {
    this.nonce = nonce;
    return this;
  }
  
  public IdTokenBuilder customClaim(String name, String value) {
    this.customClaims.put(name, value);
    return this;
  }

  public String build() throws JOSEException {
    JWTClaimsSet.Builder idClaims = new JWTClaimsSet.Builder();
    idClaims.issueTime(issueTime);
    idClaims.expirationTime(expirationTime);
    idClaims.jwtID(jwtId);

    if (audience != null && audience.size() > 0) {
      idClaims.audience(audience);
    }

    idClaims.issuer(issuer);
    idClaims.subject(sub);

    if (!Strings.isNullOrEmpty(nonce)) {
      idClaims.claim("nonce", nonce);
    }

    SignedJWT idToken;

    String keyId = keyStore.getKeys().get(0).getKeyID();
    idClaims.claim("kid", keyId);
    
    customClaims.forEach((k,v)->{
      idClaims.claim(k, v);
    });

    JWSHeader header = new JWSHeader.Builder(signingAlgo).keyID(keyId).build();

    idToken = new SignedJWT(header, idClaims.build());

    idToken.sign(signer);

    return idToken.serialize();
  }
}
