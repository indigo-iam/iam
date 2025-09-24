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
package it.infn.mw.iam.core.web.federation;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jose.JOSEException;

import it.infn.mw.iam.core.oidc.EntityConfigurationBuilder;

@RestController
@Profile("openid-federation")
public class EntityConfigurationEndpoint {

  @Value("${openid-federation.entity-configuration.expiration-seconds}")
  private int maxAge;


  private final EntityConfigurationBuilder entityConfigurationBuilder;

  public EntityConfigurationEndpoint(EntityConfigurationBuilder entityConfigurationBuilder) {
    this.entityConfigurationBuilder = entityConfigurationBuilder;
  }

  @GetMapping(value = "/.well-known/openid-federation",
      produces = "application/entity-statement+jwt")
  public ResponseEntity<byte[]> getEntityConfiguration() throws JOSEException {
    String ecJwt = entityConfigurationBuilder.build();
    return ResponseEntity.ok()
      .cacheControl(CacheControl.maxAge(maxAge, TimeUnit.SECONDS).noTransform().mustRevalidate())
      .body(ecJwt.getBytes(StandardCharsets.US_ASCII));
  }
}
