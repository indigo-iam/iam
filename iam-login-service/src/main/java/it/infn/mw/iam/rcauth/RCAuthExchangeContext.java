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
package it.infn.mw.iam.rcauth;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.UUID;

import it.infn.mw.iam.rcauth.x509.CertificateRequestHolder;

public class RCAuthExchangeContext implements Serializable{

  /**
   * 
   */
  private static final long serialVersionUID = 1L;
  
  
  private final String contextId;
  private String state;
  private String code;
  private String nonce;
  private String authorizationUrl;
  private RCAuthTokenResponse tokenResponse;
  private CertificateRequestHolder certificateRequest;
  private X509Certificate certificate;

  private RCAuthExchangeContext() {
    contextId = UUID.randomUUID().toString();
  }

  public String getAuthorizationUrl() {
    return authorizationUrl;
  }

  public void setAuthorizationUrl(String authorizationUrl) {
    this.authorizationUrl = authorizationUrl;
  }

  public RCAuthTokenResponse getTokenResponse() {
    return tokenResponse;
  }

  public void setTokenResponse(RCAuthTokenResponse tokenResponse) {
    this.tokenResponse = tokenResponse;
  }

  public CertificateRequestHolder getCertificateRequest() {
    return certificateRequest;
  }

  public void setCertificateRequest(CertificateRequestHolder certificateRequest) {
    this.certificateRequest = certificateRequest;
  }

  public X509Certificate getCertificate() {
    return certificate;
  }

  public void setCertificate(X509Certificate certificate) {
    this.certificate = certificate;
  }

  public String getContextId() {
    return contextId;
  }

  public String getCode() {
    return code;
  }

  public void setCode(String code) {
    this.code = code;
  }

  public String getNonce() {
    return nonce;
  }

  public void setNonce(String nonce) {
    this.nonce = nonce;
  }

  public String getState() {
    return state;
  }

  public void setState(String state) {
    this.state = state;
  }

  public static RCAuthExchangeContext newContext() {
    return new RCAuthExchangeContext();
  }

  @Override
  public String toString() {
    return "RCAuthExchangeContext [contextId=" + contextId + ", state=" + state + ", code=" + code
        + ", nonce=" + nonce + ", authorizationUrl=" + authorizationUrl + ", tokenResponse="
        + tokenResponse + ", certificateRequest=" + certificateRequest + ", certificate="
        + certificate + "]";
  }

}
