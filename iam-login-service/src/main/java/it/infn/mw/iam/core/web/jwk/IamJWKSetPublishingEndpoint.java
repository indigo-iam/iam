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
package it.infn.mw.iam.core.web.jwk;

import java.util.ArrayList;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

import it.infn.mw.iam.core.jwk.IamJWTSigningService;

@RestController
public class IamJWKSetPublishingEndpoint implements InitializingBean {

  public static final String URL = "jwk";

  private String jsonKeys;

  @Autowired
  private IamJWTSigningService jwtService;
  
  @Value("${spring.web.resources.cache.cachecontrol.max-age}")
  private int maxAge;

  @GetMapping(value = "/" + URL, produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public ResponseEntity<String> getJwk() {
    return ResponseEntity.ok().cacheControl(CacheControl.maxAge(maxAge, TimeUnit.SECONDS).noTransform().mustRevalidate()).body(jsonKeys);
  }

  /**
   * @return the jwtService
   */
  public JWTSigningAndValidationService getJwtService() {
    return jwtService;
  }

  /**
   * @param jwtService the jwtService to set
   */
  public void setJwtService(IamJWTSigningService jwtService) {
    this.jwtService = jwtService;
  }

  @Override
  public void afterPropertiesSet() throws Exception {

    Map<String, JWK> keys = jwtService.getAllPublicKeys();
    jsonKeys = new JWKSet(new ArrayList<>(keys.values())).toString();
  }

}
