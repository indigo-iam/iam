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
package it.infn.mw.iam.core.web.wellknown;

import static com.google.common.collect.Lists.newArrayList;
import static com.google.common.collect.Maps.newHashMap;
import static java.util.stream.Collectors.toList;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.mitre.jwt.encryption.service.JWTEncryptionAndDecryptionService;
import org.mitre.oauth2.model.PKCEAlgorithm;
import org.mitre.oauth2.service.SystemScopeService;
import org.mitre.oauth2.web.DeviceEndpoint;
import org.mitre.oauth2.web.IntrospectionEndpoint;
import org.mitre.oauth2.web.RevocationEndpoint;
import org.mitre.openid.connect.web.UserInfoEndpoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;

import it.infn.mw.iam.api.client.registration.ClientRegistrationApiController;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.web.jwk.IamJWKSetPublishingEndpoint;

@Service
public class IamWellKnownInfoProvider implements WellKnownInfoProvider {

  private static final Logger LOG = LoggerFactory.getLogger(IamWellKnownInfoProvider.class);

  public static final String CACHE_KEY = "well-known-config";

  public static final String AUTHORIZE_ENDPOINT = "authorize";
  public static final String TOKEN_ENDPOINT = "token";
  public static final String ABOUT_ENDPOINT = "about";

  private static final List<String> TOKEN_ENDPOINT_AUTH_METHODS = newArrayList(
      "client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt", "none");

  private static final List<String> RESPONSE_TYPES = newArrayList("code", "token");

  private static final List<String> SUBJECT_TYPES = newArrayList("public", "pairwise");

  private static final List<String> CLAIM_TYPES = newArrayList("normal");

  private static final List<String> CLAIMS =
      newArrayList("sub", "name", "preferred_username", "given_name", "family_name", "middle_name",
          "nickname", "profile", "picture", "zoneinfo", "locale", "updated_at", "email",
          "email_verified", "organisation_name", "groups", "wlcg.groups", "external_authn");

  private static final List<String> GRANT_TYPES =
      newArrayList("authorization_code", "implicit", "refresh_token", "client_credentials",
          "password", "urn:ietf:params:oauth:grant-type:token-exchange",
          "urn:ietf:params:oauth:grant-type:device_code");

  private static final List<String> SIGNING_ALGOS =
      newArrayList(JWSAlgorithm.HS256, JWSAlgorithm.HS384, JWSAlgorithm.HS512, JWSAlgorithm.RS256,
          JWSAlgorithm.RS384, JWSAlgorithm.RS512, JWSAlgorithm.ES256, JWSAlgorithm.ES384,
          JWSAlgorithm.ES512, JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512).stream()
            .map(JWSAlgorithm::getName)
            .collect(toList());

  private static final List<String> CODE_CHALLENGE_METHODS =
      newArrayList(PKCEAlgorithm.plain.getName(), PKCEAlgorithm.S256.getName());

  private static final List<String> USERINFO_JWS_ALGOS_SUPPORTED = SIGNING_ALGOS;

  private static final List<String> ID_TOKEN_JWS_ALGOS_SUPPORTED;

  static {
    ID_TOKEN_JWS_ALGOS_SUPPORTED = newArrayList(SIGNING_ALGOS);
    ID_TOKEN_JWS_ALGOS_SUPPORTED.add(Algorithm.NONE.getName());
  }

  private final IamProperties properties;
  private final SystemScopeService systemScopeService;

  private final List<String> allEncryptionAlgs;
  private final List<String> allEncryptionEncs;

  private final String authorizeEndpoint;
  private final String tokenEndpoint;
  private final String userinfoEndpoint;
  private final String jwkEndpoint;
  private final String clientRegistrationEndpoint;
  private final String introspectionEndpoint;
  private final String revocationEndpoint;
  private final String deviceAuthorizationEndpoint;
  private final String aboutEndpoint;
  private Set<String> supportedScopes;
  

  public IamWellKnownInfoProvider(IamProperties properties,
      JWTEncryptionAndDecryptionService encService, SystemScopeService scopeService) {
    this.properties = properties;
    this.systemScopeService = scopeService;

    allEncryptionAlgs = encService.getAllEncryptionAlgsSupported()
      .stream()
      .map(JWEAlgorithm::getName)
      .collect(toList());

    allEncryptionEncs = encService.getAllEncryptionEncsSupported()
      .stream()
      .map(EncryptionMethod::getName)
      .collect(toList());

    authorizeEndpoint = buildEndpointUrl(AUTHORIZE_ENDPOINT);
    tokenEndpoint = buildEndpointUrl(TOKEN_ENDPOINT);
    userinfoEndpoint = buildEndpointUrl(UserInfoEndpoint.URL);
    jwkEndpoint = buildEndpointUrl(IamJWKSetPublishingEndpoint.URL);
    clientRegistrationEndpoint = buildEndpointUrl(ClientRegistrationApiController.ENDPOINT);
    introspectionEndpoint = buildEndpointUrl(IntrospectionEndpoint.URL);
    revocationEndpoint = buildEndpointUrl(RevocationEndpoint.URL);
    deviceAuthorizationEndpoint = buildEndpointUrl(DeviceEndpoint.URL);
    aboutEndpoint = buildEndpointUrl(ABOUT_ENDPOINT);
    updateSupportedScopes();
  }

  protected void updateSupportedScopes() {
    supportedScopes = systemScopeService.toStrings(systemScopeService.getUnrestricted());
  }

  private String buildEndpointUrl(String endpoint) {
    String e = endpoint;
    if (endpoint.startsWith("/")) {
      e = endpoint.substring(1);
    }
    return String.format("%s/%s", properties.getBaseUrl(), e);
  }

  /**
   * FIXIME: This hack is mainly required to have the mitreid dashboard work as expected, and should
   * be removed as soon as the mitre dashboard is dropped.
   * 
   * @return the issuer URI with a trailing slash
   */
  private String getIssuerWithTrailingSlash() {
    if (properties.getIssuer().endsWith("/")) {
      return properties.getIssuer();
    } else {
      return properties.getIssuer() + "/";
    }
  }

  @Override
  @Cacheable(CACHE_KEY)
  public Map<String, Object> getWellKnownInfo() {

    Map<String, Object> result = newHashMap();

    result.put("issuer", getIssuerWithTrailingSlash());

    result.put("authorization_endpoint", authorizeEndpoint);
    result.put("token_endpoint", tokenEndpoint);

    result.put("userinfo_endpoint", userinfoEndpoint);
    result.put("jwks_uri", jwkEndpoint);
    result.put("registration_endpoint", clientRegistrationEndpoint);

    result.put("introspection_endpoint", introspectionEndpoint );
    result.put("revocation_endpoint", revocationEndpoint);
    result.put("device_authorization_endpoint", deviceAuthorizationEndpoint);

    result.put("op_policy_uri", aboutEndpoint);
    result.put("op_tos_uri", aboutEndpoint);

    result.put("response_types_supported", RESPONSE_TYPES);
    result.put("grant_types_supported", GRANT_TYPES);

    result.put("subject_types_supported", SUBJECT_TYPES);

    result.put("userinfo_signing_alg_values_supported", USERINFO_JWS_ALGOS_SUPPORTED);
    result.put("userinfo_encryption_alg_values_supported", allEncryptionAlgs);
    result.put("userinfo_encryption_enc_values_supported", allEncryptionEncs);

    result.put("id_token_signing_alg_values_supported", ID_TOKEN_JWS_ALGOS_SUPPORTED);
    result.put("id_token_encryption_alg_values_supported", allEncryptionAlgs);
    result.put("id_token_encryption_enc_values_supported", allEncryptionEncs);

    result.put("request_object_signing_alg_values_supported", SIGNING_ALGOS);
    result.put("request_object_encryption_alg_values_supported", allEncryptionAlgs);
    result.put("request_object_encryption_enc_values_supported", allEncryptionEncs);

    result.put("token_endpoint_auth_methods_supported", TOKEN_ENDPOINT_AUTH_METHODS);

    result.put("token_endpoint_auth_signing_alg_values_supported", SIGNING_ALGOS);

    result.put("claim_types_supported", CLAIM_TYPES);
    result.put("claims_supported", CLAIMS);

    result.put("claims_parameter_supported", false);
    result.put("request_parameter_supported", true);
    result.put("request_uri_parameter_supported", false);
    result.put("require_request_uri_registration", false);

    result.put("code_challenge_methods_supported", CODE_CHALLENGE_METHODS);

    result.put("scopes_supported", supportedScopes);
    
    return result;
  }

  @Scheduled(fixedDelay = 5, timeUnit = TimeUnit.MINUTES)
  @CacheEvict(allEntries = true, cacheNames = CACHE_KEY)
  protected void evictCacheAndUpdateSupportedScopes() {
    updateSupportedScopes();
    LOG.debug("well-known config cache evicted");
  }
}
