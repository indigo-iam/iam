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
package it.infn.mw.iam.authn.oidc.model;

import java.util.List;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;

public class ServerConfiguration {

  private String authorizationEndpointUri;

  private String tokenEndpointUri;

  private String registrationEndpointUri;

  private String issuer;

  private String jwksUri;

  private String userInfoUri;

  private String introspectionEndpointUri;

  private String revocationEndpointUri;

  private String checkSessionIframe;

  private String endSessionEndpoint;

  private List<String> scopesSupported;

  private List<String> responseTypesSupported;

  private List<String> grantTypesSupported;

  private List<String> acrValuesSupported;

  private List<String> subjectTypesSupported;

  private List<JWSAlgorithm> userinfoSigningAlgValuesSupported;

  private List<JWEAlgorithm> userinfoEncryptionAlgValuesSupported;

  private List<EncryptionMethod> userinfoEncryptionEncValuesSupported;

  private List<JWSAlgorithm> idTokenSigningAlgValuesSupported;

  private List<JWEAlgorithm> idTokenEncryptionAlgValuesSupported;

  private List<EncryptionMethod> idTokenEncryptionEncValuesSupported;

  private List<JWSAlgorithm> requestObjectSigningAlgValuesSupported;

  private List<JWEAlgorithm> requestObjectEncryptionAlgValuesSupported;

  private List<EncryptionMethod> requestObjectEncryptionEncValuesSupported;

  private List<String> tokenEndpointAuthMethodsSupported;

  private List<JWSAlgorithm> tokenEndpointAuthSigningAlgValuesSupported;

  private List<String> displayValuesSupported;

  private List<String> claimTypesSupported;

  private List<String> claimsSupported;

  private String serviceDocumentation;

  private List<String> claimsLocalesSupported;

  private List<String> uiLocalesSupported;

  private Boolean claimsParameterSupported;

  private Boolean requestParameterSupported;

  private Boolean requestUriParameterSupported;

  private Boolean requireRequestUriRegistration;

  private String opPolicyUri;

  private String opTosUri;

  private UserInfoTokenMethod userInfoTokenMethod;

  public enum UserInfoTokenMethod {
      HEADER,
      FORM,
      QUERY;
  }

  public String getAuthorizationEndpointUri() {
      return authorizationEndpointUri;
  }

  public void setAuthorizationEndpointUri(String authorizationEndpointUri) {
      this.authorizationEndpointUri = authorizationEndpointUri;
  }

  public String getTokenEndpointUri() {
      return tokenEndpointUri;
  }

  public void setTokenEndpointUri(String tokenEndpointUri) {
      this.tokenEndpointUri = tokenEndpointUri;
  }

  public String getRegistrationEndpointUri() {
      return registrationEndpointUri;
  }

  public void setRegistrationEndpointUri(String registrationEndpointUri) {
      this.registrationEndpointUri = registrationEndpointUri;
  }

  public String getIssuer() {
      return issuer;
  }

  public void setIssuer(String issuer) {
      this.issuer = issuer;
  }

  public String getJwksUri() {
      return jwksUri;
  }

  public void setJwksUri(String jwksUri) {
      this.jwksUri = jwksUri;
  }

  public String getUserInfoUri() {
      return userInfoUri;
  }

  public void setUserInfoUri(String userInfoUri) {
      this.userInfoUri = userInfoUri;
  }

  public String getIntrospectionEndpointUri() {
      return introspectionEndpointUri;
  }

  public void setIntrospectionEndpointUri(String introspectionEndpointUri) {
      this.introspectionEndpointUri = introspectionEndpointUri;
  }

  public String getCheckSessionIframe() {
      return checkSessionIframe;
  }

  public void setCheckSessionIframe(String checkSessionIframe) {
      this.checkSessionIframe = checkSessionIframe;
  }

  public String getEndSessionEndpoint() {
      return endSessionEndpoint;
  }

  public void setEndSessionEndpoint(String endSessionEndpoint) {
      this.endSessionEndpoint = endSessionEndpoint;
  }

  public List<String> getScopesSupported() {
      return scopesSupported;
  }

  public void setScopesSupported(List<String> scopesSupported) {
      this.scopesSupported = scopesSupported;
  }

  public List<String> getResponseTypesSupported() {
      return responseTypesSupported;
  }

  public void setResponseTypesSupported(List<String> responseTypesSupported) {
      this.responseTypesSupported = responseTypesSupported;
  }

  public List<String> getGrantTypesSupported() {
      return grantTypesSupported;
  }
 
  public void setGrantTypesSupported(List<String> grantTypesSupported) {
      this.grantTypesSupported = grantTypesSupported;
  }

  public List<String> getAcrValuesSupported() {
      return acrValuesSupported;
  }

  public void setAcrValuesSupported(List<String> acrValuesSupported) {
      this.acrValuesSupported = acrValuesSupported;
  }

  public List<String> getSubjectTypesSupported() {
      return subjectTypesSupported;
  }

  public void setSubjectTypesSupported(List<String> subjectTypesSupported) {
      this.subjectTypesSupported = subjectTypesSupported;
  }

  public List<JWSAlgorithm> getUserinfoSigningAlgValuesSupported() {
      return userinfoSigningAlgValuesSupported;
  }

  public void setUserinfoSigningAlgValuesSupported(List<JWSAlgorithm> userinfoSigningAlgValuesSupported) {
      this.userinfoSigningAlgValuesSupported = userinfoSigningAlgValuesSupported;
  }

  public List<JWEAlgorithm> getUserinfoEncryptionAlgValuesSupported() {
      return userinfoEncryptionAlgValuesSupported;
  }

  public void setUserinfoEncryptionAlgValuesSupported(List<JWEAlgorithm> userinfoEncryptionAlgValuesSupported) {
      this.userinfoEncryptionAlgValuesSupported = userinfoEncryptionAlgValuesSupported;
  }

  public List<EncryptionMethod> getUserinfoEncryptionEncValuesSupported() {
      return userinfoEncryptionEncValuesSupported;
  }

  public void setUserinfoEncryptionEncValuesSupported(List<EncryptionMethod> userinfoEncryptionEncValuesSupported) {
      this.userinfoEncryptionEncValuesSupported = userinfoEncryptionEncValuesSupported;
  }

  public List<JWSAlgorithm> getIdTokenSigningAlgValuesSupported() {
      return idTokenSigningAlgValuesSupported;
  }

  public void setIdTokenSigningAlgValuesSupported(List<JWSAlgorithm> idTokenSigningAlgValuesSupported) {
      this.idTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported;
  }

  public List<JWEAlgorithm> getIdTokenEncryptionAlgValuesSupported() {
      return idTokenEncryptionAlgValuesSupported;
  }

  public void setIdTokenEncryptionAlgValuesSupported(List<JWEAlgorithm> idTokenEncryptionAlgValuesSupported) {
      this.idTokenEncryptionAlgValuesSupported = idTokenEncryptionAlgValuesSupported;
  }

  public List<EncryptionMethod> getIdTokenEncryptionEncValuesSupported() {
      return idTokenEncryptionEncValuesSupported;
  }

  public void setIdTokenEncryptionEncValuesSupported(List<EncryptionMethod> idTokenEncryptionEncValuesSupported) {
      this.idTokenEncryptionEncValuesSupported = idTokenEncryptionEncValuesSupported;
  }

  public List<JWSAlgorithm> getRequestObjectSigningAlgValuesSupported() {
      return requestObjectSigningAlgValuesSupported;
  }

  public void setRequestObjectSigningAlgValuesSupported(List<JWSAlgorithm> requestObjectSigningAlgValuesSupported) {
      this.requestObjectSigningAlgValuesSupported = requestObjectSigningAlgValuesSupported;
  }

  public List<JWEAlgorithm> getRequestObjectEncryptionAlgValuesSupported() {
      return requestObjectEncryptionAlgValuesSupported;
  }

  public void setRequestObjectEncryptionAlgValuesSupported(List<JWEAlgorithm> requestObjectEncryptionAlgValuesSupported) {
      this.requestObjectEncryptionAlgValuesSupported = requestObjectEncryptionAlgValuesSupported;
  }

  public List<EncryptionMethod> getRequestObjectEncryptionEncValuesSupported() {
      return requestObjectEncryptionEncValuesSupported;
  }

  public void setRequestObjectEncryptionEncValuesSupported(List<EncryptionMethod> requestObjectEncryptionEncValuesSupported) {
      this.requestObjectEncryptionEncValuesSupported = requestObjectEncryptionEncValuesSupported;
  }

  public List<String> getTokenEndpointAuthMethodsSupported() {
      return tokenEndpointAuthMethodsSupported;
  }
 
  public void setTokenEndpointAuthMethodsSupported(List<String> tokenEndpointAuthMethodsSupported) {
      this.tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported;
  }

  public List<JWSAlgorithm> getTokenEndpointAuthSigningAlgValuesSupported() {
      return tokenEndpointAuthSigningAlgValuesSupported;
  }

  public void setTokenEndpointAuthSigningAlgValuesSupported(List<JWSAlgorithm> tokenEndpointAuthSigningAlgValuesSupported) {
      this.tokenEndpointAuthSigningAlgValuesSupported = tokenEndpointAuthSigningAlgValuesSupported;
  }

  public List<String> getDisplayValuesSupported() {
      return displayValuesSupported;
  }

  public void setDisplayValuesSupported(List<String> displayValuesSupported) {
      this.displayValuesSupported = displayValuesSupported;
  }

  public List<String> getClaimTypesSupported() {
      return claimTypesSupported;
  }

  public void setClaimTypesSupported(List<String> claimTypesSupported) {
      this.claimTypesSupported = claimTypesSupported;
  }

  public List<String> getClaimsSupported() {
      return claimsSupported;
  }

  public void setClaimsSupported(List<String> claimsSupported) {
      this.claimsSupported = claimsSupported;
  }

  public String getServiceDocumentation() {
      return serviceDocumentation;
  }

  public void setServiceDocumentation(String serviceDocumentation) {
      this.serviceDocumentation = serviceDocumentation;
  }

  public List<String> getClaimsLocalesSupported() {
      return claimsLocalesSupported;
  }

  public void setClaimsLocalesSupported(List<String> claimsLocalesSupported) {
      this.claimsLocalesSupported = claimsLocalesSupported;
  }

  public List<String> getUiLocalesSupported() {
      return uiLocalesSupported;
  }

  public void setUiLocalesSupported(List<String> uiLocalesSupported) {
      this.uiLocalesSupported = uiLocalesSupported;
  }

  public Boolean getClaimsParameterSupported() {
      return claimsParameterSupported;
  }

  public void setClaimsParameterSupported(Boolean claimsParameterSupported) {
      this.claimsParameterSupported = claimsParameterSupported;
  }

  public Boolean getRequestParameterSupported() {
      return requestParameterSupported;
  }

  public void setRequestParameterSupported(Boolean requestParameterSupported) {
      this.requestParameterSupported = requestParameterSupported;
  }

  public Boolean getRequestUriParameterSupported() {
      return requestUriParameterSupported;
  }

  public void setRequestUriParameterSupported(Boolean requestUriParameterSupported) {
      this.requestUriParameterSupported = requestUriParameterSupported;
  }

  public Boolean getRequireRequestUriRegistration() {
      return requireRequestUriRegistration;
  }

  public void setRequireRequestUriRegistration(Boolean requireRequestUriRegistration) {
      this.requireRequestUriRegistration = requireRequestUriRegistration;
  }

  public String getOpPolicyUri() {
      return opPolicyUri;
  }

  public void setOpPolicyUri(String opPolicyUri) {
      this.opPolicyUri = opPolicyUri;
  }

  public String getOpTosUri() {
      return opTosUri;
  }

  public void setOpTosUri(String opTosUri) {
      this.opTosUri = opTosUri;
  }

  public String getRevocationEndpointUri() {
      return revocationEndpointUri;
  }

  public void setRevocationEndpointUri(String revocationEndpointUri) {
      this.revocationEndpointUri = revocationEndpointUri;
  }

  public UserInfoTokenMethod getUserInfoTokenMethod() {
      return userInfoTokenMethod;
  }

  public void setUserInfoTokenMethod(UserInfoTokenMethod userInfoTokenMethod) {
      this.userInfoTokenMethod = userInfoTokenMethod;
  }

 
}
