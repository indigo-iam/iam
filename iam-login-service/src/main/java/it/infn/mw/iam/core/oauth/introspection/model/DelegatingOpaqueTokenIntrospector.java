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
package it.infn.mw.iam.core.oauth.introspection.model;

import java.text.ParseException;

import java.util.List;
import java.util.Map;
import java.util.function.Function;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.SpringOpaqueTokenIntrospector;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.config.oidc.OidcClient;
import it.infn.mw.iam.config.oidc.OidcProvider;
import it.infn.mw.iam.config.oidc.OidcProviderProperties;
import it.infn.mw.iam.core.oauth.discovery.OidcDiscoveryService;

@SuppressWarnings("deprecation")
@Component
public class DelegatingOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

  private static final Logger LOG = LoggerFactory.getLogger(DelegatingOpaqueTokenIntrospector.class);

  private static final String INTROSPECTION_ENDPOINT_KEY = "introspection_endpoint";

  private final OidcProviderProperties properties;
  private final Function<OidcClient, RestTemplate> restTemplateMapper;
  private final OidcDiscoveryService discoveryService;

  public DelegatingOpaqueTokenIntrospector(OidcProviderProperties properties,
      Function<OidcClient, RestTemplate> restTemplateMapper,
      OidcDiscoveryService discoveryService) {

    this.properties = properties;
    this.restTemplateMapper = restTemplateMapper;
    this.discoveryService = discoveryService;
  }

  @Override
  public OAuth2AuthenticatedPrincipal introspect(String token) {

    final String issuer;

    try {
      issuer = JWTParser.parse(token).getJWTClaimsSet().getIssuer();
    } catch (ParseException e) {
        LOG.info("Failed introspection of token, parsing exception {}", e.getMessage());
        return inactive();
    }

    OidcProvider provider = properties.getProviders().stream().filter(c -> c.getIssuer().equals(issuer))
        .findFirst()
        .orElseThrow(() -> new InvalidTokenException("Invalid issuer: " + issuer));

    RestTemplate restTemplate = restTemplateMapper.apply(provider.getClient());

    /** 
    * Declaration of the JSON node that contains the discovery document of the
    * issuer.
    * Makes a GET call to issuer/.well-known/openid-configuration or,
    * /.well-known/oauth-authorization-server and gives the OIDC configuration in
    * JSON
    */
    JsonNode discovery = discoveryService.getDiscoveryDocument(issuer, restTemplate);
    /**
    * Verifies that the discovery document has an introspection_endpoint field
    * and extracts it as a string
    */   
    String introspectionEndpoint = discovery.has(INTROSPECTION_ENDPOINT_KEY)
        ? discovery.get(INTROSPECTION_ENDPOINT_KEY).asText()
        : null;
    /** 
    * If the field doesn't exist or is blank, the token is invalid and the issuer
    * doesnt't support introspection
    */ 
    if (introspectionEndpoint == null || introspectionEndpoint.isBlank()) {
        LOG.info("Failed introspection of token, no introspection endpoint found for {}", issuer);
        return inactive();
    }

    OpaqueTokenIntrospector introspector = new SpringOpaqueTokenIntrospector(introspectionEndpoint, restTemplate);
    try{
      return introspector.introspect(token);
    } catch (Throwable t) {
      LOG.error("Failed introspection of token issued by {}: {}", issuer, t.getMessage());
      return inactive();
    }
  }

  private OAuth2AuthenticatedPrincipal inactive(){
    return new DefaultOAuth2AuthenticatedPrincipal(Map.of("active", false), List.of());
  }
  
}

