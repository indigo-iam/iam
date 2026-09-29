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
package it.infn.mw.iam.core.jwk;

import java.util.Collection;
import java.util.Map;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;

public interface JWTSigningAndValidationService {

  public Map<String, JWK> getAllPublicKeys();

  public boolean validateSignature(SignedJWT jwtString);

  public void signJwt(SignedJWT jwt);

  public JWSAlgorithm getDefaultSigningAlgorithm();

  public Collection<JWSAlgorithm> getAllSigningAlgsSupported();

  public void signJwt(SignedJWT jwt, JWSAlgorithm alg);

  public String getDefaultSignerKeyId();

}