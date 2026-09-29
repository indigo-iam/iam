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

import static java.util.stream.Collectors.toList;

import java.util.List;
import java.util.Set;

import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;

import it.infn.mw.iam.api.client.registration.ClientRegistrationApiController;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.jwk.JWTEncryptionAndDecryptionService;
import it.infn.mw.iam.core.oauth.IamDeviceEndpointController;
import it.infn.mw.iam.core.oauth.introspection.IamIntrospectionEndpoint;
import it.infn.mw.iam.core.oauth.revocation.IamRevocationEndpoint;
import it.infn.mw.iam.core.oauth.scope.SystemScopeService;
import it.infn.mw.iam.core.userinfo.IamUserInfoEndpoint;
import it.infn.mw.iam.core.web.jwk.IamJWKSetPublishingEndpoint;
import it.infn.mw.iam.persistence.model.PKCEAlgorithm;

@Service
public class IamWellKnownInfoProvider implements WellKnownInfoProvider {

  public static final String CACHE_KEY = "well-known-config";

  public static final String AUTHORIZE_ENDPOINT = "authorize";
  public static final String TOKEN_ENDPOINT = "token";
  public static final String ABOUT_ENDPOINT = "about";
  public static final String SCIM_ENDPOINT = "scim";
  public static final String LOGOUT_ENDPOINT = "logout";

  private static final List<String> TOKEN_ENDPOINT_AUTH_METHODS = List.of("client_secret_basic",
      "client_secret_post", "client_secret_jwt", "private_key_jwt", "none");

  private static final List<String> RESPONSE_TYPES = List.of("code", "token");

  private static final List<String> SUBJECT_TYPES = List.of("public", "pairwise");

  private static final List<String> CLAIM_TYPES = List.of("normal");

  private static final List<String> CLAIMS =
      List.of("sub", "name", "preferred_username", "given_name", "family_name", "middle_name",
          "nickname", "profile", "picture", "zoneinfo", "locale", "updated_at", "email",
          "email_verified", "organisation_name", "groups", "wlcg.groups", "external_authn");

  private static final List<String> GRANT_TYPES =
      List.of("authorization_code", "implicit", "refresh_token", "client_credentials", "password",
          "urn:ietf:params:oauth:grant-type:token-exchange",
          "urn:ietf:params:oauth:grant-type:device_code");

  public static final List<JWSAlgorithm> SIGNING_ALGOS = List.of(JWSAlgorithm.RS256,
      JWSAlgorithm.RS384, JWSAlgorithm.RS512, JWSAlgorithm.ES256, JWSAlgorithm.ES384,
      JWSAlgorithm.ES512, JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512);

  private static final List<PKCEAlgorithm> CODE_CHALLENGE_METHODS =
      List.of(PKCEAlgorithm.PLAIN, PKCEAlgorithm.S256);

  private static final List<JWSAlgorithm> USERINFO_JWS_ALGOS_SUPPORTED = SIGNING_ALGOS;

  private static final List<Algorithm> ID_TOKEN_JWS_ALGOS_SUPPORTED =
      List.of(JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512, JWSAlgorithm.ES256,
          JWSAlgorithm.ES384, JWSAlgorithm.ES512, JWSAlgorithm.PS256, JWSAlgorithm.PS384,
          JWSAlgorithm.PS512, Algorithm.NONE);

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
  private final String scimEndpoint;
  private final String logoutEndpoint;
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
    userinfoEndpoint = buildEndpointUrl(IamUserInfoEndpoint.URL);
    jwkEndpoint = buildEndpointUrl(IamJWKSetPublishingEndpoint.URL);
    clientRegistrationEndpoint = buildEndpointUrl(ClientRegistrationApiController.ENDPOINT);
    introspectionEndpoint = buildEndpointUrl(IamIntrospectionEndpoint.URL);
    revocationEndpoint = buildEndpointUrl(IamRevocationEndpoint.URL);
    deviceAuthorizationEndpoint = buildEndpointUrl(IamDeviceEndpointController.DEVICE_CODE_URL);
    aboutEndpoint = buildEndpointUrl(ABOUT_ENDPOINT);
    scimEndpoint = buildEndpointUrl(SCIM_ENDPOINT);
    logoutEndpoint = buildEndpointUrl(LOGOUT_ENDPOINT);
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

  @Override
  @Cacheable(value = CACHE_KEY)
  public WellKnownConfiguration getWellKnownInfo() {

    updateSupportedScopes();

    return WellKnownConfiguration.builder()
      .issuer(properties.getIssuer())
      .authorizationEndpoint(authorizeEndpoint)
      .tokenEndpoint(tokenEndpoint)
      .userinfoEndpoint(userinfoEndpoint)
      .jwksUri(jwkEndpoint)
      .registrationEndpoint(clientRegistrationEndpoint)
      .introspectionEndpoint(introspectionEndpoint)
      .revocationEndpoint(revocationEndpoint)
      .deviceAuthorizationEndpoint(deviceAuthorizationEndpoint)
      .opPolicyUri(aboutEndpoint)
      .opTosUri(aboutEndpoint)
      .scimEndpoint(scimEndpoint)
      .responseTypesSupported(RESPONSE_TYPES)
      .grantTypesSupported(GRANT_TYPES)
      .subjectTypesSupported(SUBJECT_TYPES)
      .userinfoSigningAlgValuesSupported(USERINFO_JWS_ALGOS_SUPPORTED)
      .userinfoEncryptionAlgValuesSupported(allEncryptionAlgs)
      .userinfoEncryptionEncValuesSupported(allEncryptionEncs)
      .idTokenSigningAlgValuesSupported(ID_TOKEN_JWS_ALGOS_SUPPORTED)
      .idTokenEncryptionAlgValuesSupported(allEncryptionAlgs)
      .idTokenEncryptionEncValuesSupported(allEncryptionEncs)
      .requestObjectSigningAlgValuesSupported(SIGNING_ALGOS)
      .requestObjectEncryptionAlgValuesSupported(allEncryptionAlgs)
      .requestObjectEncryptionEncValuesSupported(allEncryptionEncs)
      .tokenEndpointAuthMethodsSupported(TOKEN_ENDPOINT_AUTH_METHODS)
      .tokenEndpointAuthSigningAlgValuesSupported(SIGNING_ALGOS)
      .claimTypesSupported(CLAIM_TYPES)
      .claimsSupported(CLAIMS)
      .claimsParameterSupported(true)
      .requestParameterSupported(true)
      .requestUriParameterSupported(false)
      .requireRequestUriRegistration(false)
      .codeChallengeMethodsSupported(CODE_CHALLENGE_METHODS)
      .scopesSupported(supportedScopes)
      .endSessionEndpoint(logoutEndpoint)
      .build();
  }

}
