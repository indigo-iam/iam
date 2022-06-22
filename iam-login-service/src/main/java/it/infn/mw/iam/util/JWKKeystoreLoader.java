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

import org.mitre.jose.keystore.JWKSetKeyStore;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import it.infn.mw.iam.config.error.IAMJWTKeystoreError;

public class JWKKeystoreLoader {

  final ResourceLoader loader;

  public JWKKeystoreLoader(ResourceLoader resourceLoader) {
    this.loader = resourceLoader;
  }

  public JWKSetKeyStore loadKeystoreFromLocation(String keyStoreLocation) {
    try {
      Resource keyStoreResource = loader.getResource(keyStoreLocation);

      JWKSetKeyStore keyStore = new JWKSetKeyStore();
      keyStore.setLocation(keyStoreResource);

      return keyStore;
    } catch (Exception e) {
      throw new IAMJWTKeystoreError("Error initializing JWKProperties keystore: " + e.getMessage(), e);
    }
  }

}
