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
package it.infn.mw.iam.core.oidc.service;

public class IssuerServiceResponse {

  private String issuer;
  private String loginHint;
  private String targetLinkUri;
  private String redirectUrl;

  public IssuerServiceResponse(String issuer, String loginHint, String targetLinkUri) {
    this.issuer = issuer;
    this.loginHint = loginHint;
    this.targetLinkUri = targetLinkUri;
  }

  public IssuerServiceResponse(String redirectUrl) {
    this.redirectUrl = redirectUrl;
  }

  public String getIssuer() {
    return issuer;
  }

  public void setIssuer(String issuer) {
    this.issuer = issuer;
  }

  public String getLoginHint() {
    return loginHint;
  }

  public void setLoginHint(String loginHint) {
    this.loginHint = loginHint;
  }

  public String getTargetLinkUri() {
    return targetLinkUri;
  }

  public void setTargetLinkUri(String targetLinkUri) {
    this.targetLinkUri = targetLinkUri;
  }

  public String getRedirectUrl() {
    return redirectUrl;
  }

  public void setRedirectUrl(String redirectUrl) {
    this.redirectUrl = redirectUrl;
  }

  public boolean shouldRedirect() {
    return this.redirectUrl != null;
  }

}
