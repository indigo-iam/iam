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
package it.infn.mw.iam.authn.saml.profile;

import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.springframework.security.saml.websso.WebSSOProfileOptions;

public class IamSSOProfileOptions extends WebSSOProfileOptions {

  public IamSSOProfileOptions() {
    setIncludeScoping(false);
  }
  
  private static final long serialVersionUID = 1L;

  public enum SpidAuthenticationLevel {
    SpidL1("https://www.spid.gov.it/SpidL1"),
    SpidL2("https://www.spid.gov.it/SpidL2"),
    SpidL3("https://www.spid.gov.it/SpidL3");
    
    private String url;
    
    private SpidAuthenticationLevel(String url) {
      this.url = url;
    }
    
    public String getUrl() {
      return url;
    }
  }
  public enum AuthnContextComparison {
    exact(AuthnContextComparisonTypeEnumeration.EXACT),
    minimum(AuthnContextComparisonTypeEnumeration.MINIMUM),
    maximum(AuthnContextComparisonTypeEnumeration.MAXIMUM),
    better(AuthnContextComparisonTypeEnumeration.BETTER);

    AuthnContextComparisonTypeEnumeration comparison;

    private AuthnContextComparison(AuthnContextComparisonTypeEnumeration cmp) {
      this.comparison = cmp;
    }

    public AuthnContextComparisonTypeEnumeration getComparison() {
      return comparison;
    }
  };

  private Integer attributeConsumerIndex = 0;
  
  private Boolean spidIdp = false;

  private AuthnContextComparison authnContextComparisonEnum = AuthnContextComparison.minimum;

  private SpidAuthenticationLevel spidAuthenticationLevel = SpidAuthenticationLevel.SpidL1;
  
  public Boolean getSpidIdp() {
    return spidIdp;
  }

  public void setSpidIdp(Boolean spidIdp) {
    this.spidIdp = spidIdp;
  }

  public AuthnContextComparison getAuthnContextComparisonEnum() {
    return authnContextComparisonEnum;
  }

  public void setAuthnContextComparisonEnum(AuthnContextComparison authnContextComparisonEnum) {
    this.authnContextComparisonEnum = authnContextComparisonEnum;
  }

  public Integer getAttributeConsumerIndex() {
    return attributeConsumerIndex;
  }

  public void setAttributeConsumerIndex(Integer attributeConsumerIndex) {
    this.attributeConsumerIndex = attributeConsumerIndex;
  }
  
  public void setSpidAuthenticationLevel(SpidAuthenticationLevel spidAuthenticationLevel) {
    this.spidAuthenticationLevel = spidAuthenticationLevel;
  }
  
  public SpidAuthenticationLevel getSpidAuthenticationLevel() {
    return spidAuthenticationLevel;
  }
  
}
