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

import java.util.List;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;

import it.infn.mw.iam.persistence.model.PKCEAlgorithm;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record WellKnownConfiguration(

    String issuer, @JsonProperty("authorization_endpoint") String authorizationEndpoint,
    @JsonProperty("token_endpoint") String tokenEndpoint,
    @JsonProperty("userinfo_endpoint") String userinfoEndpoint,
    @JsonProperty("jwks_uri") String jwksUri,
    @JsonProperty("registration_endpoint") String registrationEndpoint,
    @JsonProperty("introspection_endpoint") String introspectionEndpoint,
    @JsonProperty("revocation_endpoint") String revocationEndpoint,
    @JsonProperty("device_authorization_endpoint") String deviceAuthorizationEndpoint,
    @JsonProperty("op_policy_uri") String opPolicyUri, @JsonProperty("op_tos_uri") String opTosUri,
    @JsonProperty("scim_endpoint") String scimEndpoint,
    @JsonProperty("response_types_supported") List<String> responseTypesSupported,
    @JsonProperty("grant_types_supported") List<String> grantTypesSupported,
    @JsonProperty("subject_types_supported") List<String> subjectTypesSupported,
    @JsonProperty("userinfo_signing_alg_values_supported") List<String> userinfoSigningAlgValuesSupported,
    @JsonProperty("userinfo_encryption_alg_values_supported") List<String> userinfoEncryptionAlgValuesSupported,
    @JsonProperty("userinfo_encryption_enc_values_supported") List<String> userinfoEncryptionEncValuesSupported,
    @JsonProperty("id_token_signing_alg_values_supported") List<String> idTokenSigningAlgValuesSupported,
    @JsonProperty("id_token_encryption_alg_values_supported") List<String> idTokenEncryptionAlgValuesSupported,
    @JsonProperty("id_token_encryption_enc_values_supported") List<String> idTokenEncryptionEncValuesSupported,
    @JsonProperty("request_object_signing_alg_values_supported") List<String> requestObjectSigningAlgValuesSupported,
    @JsonProperty("request_object_encryption_alg_values_supported") List<String> requestObjectEncryptionAlgValuesSupported,
    @JsonProperty("request_object_encryption_enc_values_supported") List<String> requestObjectEncryptionEncValuesSupported,
    @JsonProperty("token_endpoint_auth_methods_supported") List<String> tokenEndpointAuthMethodsSupported,
    @JsonProperty("token_endpoint_auth_signing_alg_values_supported") List<String> tokenEndpointAuthSigningAlgValuesSupported,
    @JsonProperty("claim_types_supported") List<String> claimTypesSupported,
    @JsonProperty("claims_supported") List<String> claimsSupported,
    @JsonProperty("claims_parameter_supported") boolean claimsParameterSupported,
    @JsonProperty("request_parameter_supported") boolean requestParameterSupported,
    @JsonProperty("request_uri_parameter_supported") boolean requestUriParameterSupported,
    @JsonProperty("require_request_uri_registration") boolean requireRequestUriRegistration,
    @JsonProperty("code_challenge_methods_supported") List<PKCEAlgorithm> codeChallengeMethodsSupported,
    @JsonProperty("scopes_supported") Set<String> scopesSupported,
    @JsonProperty("end_session_endpoint") String endSessionEndpoint) {

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {

    private String issuer;
    private String authorizationEndpoint;
    private String tokenEndpoint;
    private String userinfoEndpoint;
    private String jwksUri;
    private String registrationEndpoint;
    private String introspectionEndpoint;
    private String revocationEndpoint;
    private String deviceAuthorizationEndpoint;
    private String opPolicyUri;
    private String opTosUri;
    private String scimEndpoint;
    private List<String> responseTypesSupported;
    private List<String> grantTypesSupported;
    private List<String> subjectTypesSupported;
    private List<String> userinfoSigningAlgValuesSupported;
    private List<String> userinfoEncryptionAlgValuesSupported;
    private List<String> userinfoEncryptionEncValuesSupported;
    private List<String> idTokenSigningAlgValuesSupported;
    private List<String> idTokenEncryptionAlgValuesSupported;
    private List<String> idTokenEncryptionEncValuesSupported;
    private List<String> requestObjectSigningAlgValuesSupported;
    private List<String> requestObjectEncryptionAlgValuesSupported;
    private List<String> requestObjectEncryptionEncValuesSupported;
    private List<String> tokenEndpointAuthMethodsSupported;
    private List<String> tokenEndpointAuthSigningAlgValuesSupported;
    private List<String> claimTypesSupported;
    private List<String> claimsSupported;
    private boolean claimsParameterSupported;
    private boolean requestParameterSupported;
    private boolean requestUriParameterSupported;
    private boolean requireRequestUriRegistration;
    private List<PKCEAlgorithm> codeChallengeMethodsSupported;
    private Set<String> scopesSupported;
    private String endSessionEndpoint;

    public Builder issuer(String issuer) {
      this.issuer = issuer;
      return this;
    }

    public Builder authorizationEndpoint(String authorizationEndpoint) {
      this.authorizationEndpoint = authorizationEndpoint;
      return this;
    }

    public Builder tokenEndpoint(String tokenEndpoint) {
      this.tokenEndpoint = tokenEndpoint;
      return this;
    }

    public Builder userinfoEndpoint(String userinfoEndpoint) {
      this.userinfoEndpoint = userinfoEndpoint;
      return this;
    }

    public Builder jwksUri(String jwksUri) {
      this.jwksUri = jwksUri;
      return this;
    }

    public Builder registrationEndpoint(String registrationEndpoint) {
      this.registrationEndpoint = registrationEndpoint;
      return this;
    }

    public Builder introspectionEndpoint(String introspectionEndpoint) {
      this.introspectionEndpoint = introspectionEndpoint;
      return this;
    }

    public Builder revocationEndpoint(String revocationEndpoint) {
      this.revocationEndpoint = revocationEndpoint;
      return this;
    }

    public Builder deviceAuthorizationEndpoint(String deviceAuthorizationEndpoint) {
      this.deviceAuthorizationEndpoint = deviceAuthorizationEndpoint;
      return this;
    }

    public Builder opPolicyUri(String opPolicyUri) {
      this.opPolicyUri = opPolicyUri;
      return this;
    }

    public Builder opTosUri(String opTosUri) {
      this.opTosUri = opTosUri;
      return this;
    }

    public Builder scimEndpoint(String scimEndpoint) {
      this.scimEndpoint = scimEndpoint;
      return this;
    }

    public Builder responseTypesSupported(List<String> responseTypesSupported) {
      this.responseTypesSupported = responseTypesSupported;
      return this;
    }

    public Builder grantTypesSupported(List<String> grantTypesSupported) {
      this.grantTypesSupported = grantTypesSupported;
      return this;
    }

    public Builder subjectTypesSupported(List<String> subjectTypesSupported) {
      this.subjectTypesSupported = subjectTypesSupported;
      return this;
    }

    public Builder userinfoSigningAlgValuesSupported(
        List<JWSAlgorithm> userinfoSigningAlgValuesSupported) {
      this.userinfoSigningAlgValuesSupported =
          userinfoSigningAlgValuesSupported.stream().map(JWSAlgorithm::getName).toList();
      return this;
    }

    public Builder userinfoEncryptionAlgValuesSupported(
        List<String> userinfoEncryptionAlgValuesSupported) {
      this.userinfoEncryptionAlgValuesSupported = userinfoEncryptionAlgValuesSupported;
      return this;
    }

    public Builder userinfoEncryptionEncValuesSupported(
        List<String> userinfoEncryptionEncValuesSupported) {
      this.userinfoEncryptionEncValuesSupported = userinfoEncryptionEncValuesSupported;
      return this;
    }

    public Builder idTokenSigningAlgValuesSupported(
        List<Algorithm> idTokenSigningAlgValuesSupported) {
      this.idTokenSigningAlgValuesSupported =
          idTokenSigningAlgValuesSupported.stream().map(Algorithm::getName).toList();
      return this;
    }

    public Builder idTokenEncryptionAlgValuesSupported(
        List<String> idTokenEncryptionAlgValuesSupported) {
      this.idTokenEncryptionAlgValuesSupported = idTokenEncryptionAlgValuesSupported;
      return this;
    }

    public Builder idTokenEncryptionEncValuesSupported(
        List<String> idTokenEncryptionEncValuesSupported) {
      this.idTokenEncryptionEncValuesSupported = idTokenEncryptionEncValuesSupported;
      return this;
    }

    public Builder requestObjectSigningAlgValuesSupported(
        List<JWSAlgorithm> requestObjectSigningAlgValuesSupported) {
      this.requestObjectSigningAlgValuesSupported =
          requestObjectSigningAlgValuesSupported.stream().map(JWSAlgorithm::getName).toList();
      return this;
    }

    public Builder requestObjectEncryptionAlgValuesSupported(
        List<String> requestObjectEncryptionAlgValuesSupported) {
      this.requestObjectEncryptionAlgValuesSupported = requestObjectEncryptionAlgValuesSupported;
      return this;
    }

    public Builder requestObjectEncryptionEncValuesSupported(
        List<String> requestObjectEncryptionEncValuesSupported) {
      this.requestObjectEncryptionEncValuesSupported = requestObjectEncryptionEncValuesSupported;
      return this;
    }

    public Builder tokenEndpointAuthMethodsSupported(
        List<String> tokenEndpointAuthMethodsSupported) {
      this.tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported;
      return this;
    }

    public Builder tokenEndpointAuthSigningAlgValuesSupported(
        List<JWSAlgorithm> tokenEndpointAuthSigningAlgValuesSupported) {
      this.tokenEndpointAuthSigningAlgValuesSupported =
          tokenEndpointAuthSigningAlgValuesSupported.stream().map(JWSAlgorithm::getName).toList();
      return this;
    }

    public Builder claimTypesSupported(List<String> claimTypesSupported) {
      this.claimTypesSupported = claimTypesSupported;
      return this;
    }

    public Builder claimsSupported(List<String> claimsSupported) {
      this.claimsSupported = claimsSupported;
      return this;
    }

    public Builder claimsParameterSupported(boolean claimsParameterSupported) {
      this.claimsParameterSupported = claimsParameterSupported;
      return this;
    }

    public Builder requestParameterSupported(boolean requestParameterSupported) {
      this.requestParameterSupported = requestParameterSupported;
      return this;
    }

    public Builder requestUriParameterSupported(boolean requestUriParameterSupported) {
      this.requestUriParameterSupported = requestUriParameterSupported;
      return this;
    }

    public Builder requireRequestUriRegistration(boolean requireRequestUriRegistration) {
      this.requireRequestUriRegistration = requireRequestUriRegistration;
      return this;
    }

    public Builder codeChallengeMethodsSupported(
        List<PKCEAlgorithm> codeChallengeMethodsSupported) {
      this.codeChallengeMethodsSupported = codeChallengeMethodsSupported;
      return this;
    }

    public Builder scopesSupported(Set<String> scopesSupported) {
      this.scopesSupported = scopesSupported;
      return this;
    }

    public Builder endSessionEndpoint(String endSessionEndpoint) {
      this.endSessionEndpoint = endSessionEndpoint;
      return this;
    }

    public WellKnownConfiguration build() {
      return new WellKnownConfiguration(issuer, authorizationEndpoint, tokenEndpoint,
          userinfoEndpoint, jwksUri, registrationEndpoint, introspectionEndpoint,
          revocationEndpoint, deviceAuthorizationEndpoint, opPolicyUri, opTosUri, scimEndpoint,
          responseTypesSupported, grantTypesSupported, subjectTypesSupported,
          userinfoSigningAlgValuesSupported, userinfoEncryptionAlgValuesSupported,
          userinfoEncryptionEncValuesSupported, idTokenSigningAlgValuesSupported,
          idTokenEncryptionAlgValuesSupported, idTokenEncryptionEncValuesSupported,
          requestObjectSigningAlgValuesSupported, requestObjectEncryptionAlgValuesSupported,
          requestObjectEncryptionEncValuesSupported, tokenEndpointAuthMethodsSupported,
          tokenEndpointAuthSigningAlgValuesSupported, claimTypesSupported, claimsSupported,
          claimsParameterSupported, requestParameterSupported, requestUriParameterSupported,
          requireRequestUriRegistration, codeChallengeMethodsSupported, scopesSupported,
          endSessionEndpoint);
    }
  }
}
