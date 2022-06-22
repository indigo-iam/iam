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
package it.infn.mw.iam.config.saml;

import static java.lang.Boolean.FALSE;

import javax.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "saml.idp-metadata")
public class IamSamlIdpMetadataProperties {

  @NotBlank
  private String metadataUrl;
  
  private Boolean requireValidSignature = FALSE;
  
  private Boolean requireSirtfi = FALSE;
  
  private Boolean requireRs = FALSE;
  
  private String keyAlias;
  
  public IamSamlIdpMetadataProperties() {
    // empty constructor
  }

  public String getMetadataUrl() {
    return metadataUrl;
  }

  public void setMetadataUrl(String metadataUrl) {
    this.metadataUrl = metadataUrl;
  }

  public Boolean getRequireValidSignature() {
    return requireValidSignature;
  }

  public void setRequireValidSignature(Boolean requireValidSignature) {
    this.requireValidSignature = requireValidSignature;
  }

  public Boolean getRequireSirtfi() {
    return requireSirtfi;
  }

  public void setRequireSirtfi(Boolean requireSirtfi) {
    this.requireSirtfi = requireSirtfi;
  }

  public Boolean getRequireRs() {
    return requireRs;
  }

  public void setRequireRs(Boolean requireRs) {
    this.requireRs = requireRs;
  }

  public String getKeyAlias() {
    return keyAlias;
  }

  public void setKeyAlias(String keyAlias) {
    this.keyAlias = keyAlias;
  }
}
