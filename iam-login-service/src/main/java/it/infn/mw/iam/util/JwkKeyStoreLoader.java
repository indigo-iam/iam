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
package it.infn.mw.iam.util;

import java.io.IOException;
import java.text.ParseException;
import java.util.Objects;

import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import com.nimbusds.jose.jwk.JWKSet;

import it.infn.mw.iam.config.error.IAMJWTKeystoreError;
import it.infn.mw.iam.core.jwk.JwkKeyStore;

public final class JwkKeyStoreLoader {

  private final ResourceLoader resourceLoader;

  public JwkKeyStoreLoader(ResourceLoader resourceLoader) {
    this.resourceLoader = Objects.requireNonNull(resourceLoader);
  }

  public JwkKeyStore load(String location) {
    try {
      Resource resource = resourceLoader.getResource(location);
      JWKSet jwkSet = JwkSetLoader.load(resource);
      return JwkKeyStore.from(jwkSet);

    } catch (IOException | ParseException e) {
      throw new IAMJWTKeystoreError(
          "Error loading JWK keystore from " + location, e);
    }
  }
}
