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
import java.text.ParseException;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.util.JSONObjectUtils;

import it.infn.mw.iam.core.oidc.EntityConfigurationBuilder;
import it.infn.mw.iam.core.web.jwk.IamJWKSetPublishingEndpoint;

@RestController
public class EntityConfigurationEndpoint {

  private final IamJWKSetPublishingEndpoint jwkController;
  private final EntityConfigurationBuilder builder;

  public EntityConfigurationEndpoint(IamJWKSetPublishingEndpoint jwkController,
      EntityConfigurationBuilder builder) {
    this.jwkController = jwkController;
    this.builder = builder;
  }

  @Value("${iam.issuer}")
  private String issuer;

  @GetMapping(value = "/.well-known/openid-federation",
      produces = "application/entity-statement+jwt")
  public ResponseEntity<byte[]> getEntityConfiguration() throws ParseException, JOSEException {
    String jsonKeys = jwkController.getJwk().getBody();
    Map<String, Object> jwks = JSONObjectUtils.parse(jsonKeys);
    String ecJwt = builder.buildEntityConfiguration(issuer, jwks);
    return ResponseEntity.ok().body(ecJwt.getBytes(StandardCharsets.US_ASCII));
  }
}
