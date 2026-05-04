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

import java.util.List;
import java.util.Objects;
import java.util.Optional;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

public class JwkKeyStore {

  private final List<JWK> keys;

  public JwkKeyStore(List<JWK> keys) {
    this.keys = List.copyOf(Objects.requireNonNull(keys));
  }

  public static JwkKeyStore from(JWKSet jwkSet) {
    Objects.requireNonNull(jwkSet, "jwkSet must not be null");
    return new JwkKeyStore(jwkSet.getKeys());
  }

  public List<JWK> getKeys() {
    return keys;
  }

  public Optional<JWK> findByKeyId(String kid) {
    return keys.stream().filter(k -> kid.equals(k.getKeyID())).findFirst();
  }
}
