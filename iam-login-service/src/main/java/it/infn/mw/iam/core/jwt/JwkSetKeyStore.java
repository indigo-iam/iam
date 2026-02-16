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
package it.infn.mw.iam.core.jwt;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.List;
import java.util.Objects;

import org.springframework.core.io.Resource;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

public class JwkSetKeyStore {

  private JWKSet jwkSet;

  private Resource location;

  public JwkSetKeyStore(JWKSet jwkSet) {
    Objects.requireNonNull(jwkSet);
    this.jwkSet = jwkSet;
    this.location = null;
  }

  public JwkSetKeyStore(Resource location) {
    Objects.requireNonNull(location);
    initializeJwkSetFromLocation(location);
  }

  private void initializeJwkSetFromLocation(Resource location) {

    if (!location.exists() || !location.isReadable()) {
      throw new IllegalArgumentException("Key Set resource could not be read: " + location);
    }
    try {
      String jwkStr = new String(location.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
      this.jwkSet = JWKSet.parse(jwkStr);
    } catch (IOException e) {
      throw new IllegalArgumentException("Key Set resource could not be read: " + location);
    } catch (ParseException e) {
      throw new IllegalArgumentException("Key Set resource could not be parsed: " + location);
    }
    this.location = location;
  }

  public JWKSet getJwkSet() {
    return jwkSet;
  }

  public Resource getLocation() {
    return location;
  }

  public List<JWK> getKeys() {
    if (jwkSet != null) {
      return jwkSet.getKeys();
    }
    return List.of();
  }


}
