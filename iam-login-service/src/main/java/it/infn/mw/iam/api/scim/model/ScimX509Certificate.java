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
package it.infn.mw.iam.api.scim.model;

import java.util.Date;

import org.hibernate.validator.constraints.Length;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import it.infn.mw.iam.api.scim.controller.utils.JsonDateSerializer;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class ScimX509Certificate {

  @Length(max = 36)
  private final String display;

  private final Boolean primary;
  
  @Length(max = 256)
  private final String subjectDn;

  @Length(max = 256)
  private final String issuerDn;

  private final String pemEncodedCertificate;

  @JsonSerialize(using = JsonDateSerializer.class)
  private final Date created;

  @JsonSerialize(using = JsonDateSerializer.class)
  private final Date lastModified;
  
  private final boolean hasProxyCertificate;
  
  @JsonSerialize(using = JsonDateSerializer.class)
  private final Date proxyExpirationTime;

  @JsonCreator
  private ScimX509Certificate(@JsonProperty("label") String display, @JsonProperty("primary") Boolean primary,
      @JsonProperty("subjectDn") String subjectDn, 
      @JsonProperty("issuerDn") String issuerDn,  
      @JsonProperty("pemEncodedCertificate") String pemEncodedCertificate) {

    this.display = display;
    this.primary = primary;
    this.subjectDn = subjectDn;
    this.issuerDn = issuerDn;
    this.pemEncodedCertificate = pemEncodedCertificate;
    this.created = this.lastModified = null;
    this.hasProxyCertificate = false;
    this.proxyExpirationTime = null;
  }

  private ScimX509Certificate(Builder b) {
    this.display = b.display;
    this.primary = b.primary;
    this.subjectDn = b.subjectDn;
    this.issuerDn = b.issuerDn;
    this.created = b.created;
    this.lastModified = b.lastModified;
    this.pemEncodedCertificate = b.pemEncodedCertificate;
    this.hasProxyCertificate = b.hasProxyCertificate;
    this.proxyExpirationTime = b.proxyExpirationTime;
  }

  public String getDisplay() {
    return display;
  }

  public Boolean getPrimary() {
    return primary;
  }

  public String getSubjectDn() {
    return subjectDn;
  }

  public String getPemEncodedCertificate() {
    return pemEncodedCertificate;
  }

  public String getIssuerDn() {
    return issuerDn;
  }

  public Date getCreated() {
    return created;
  }

  public Date getLastModified() {
    return lastModified;
  }
  
  public boolean isHasProxyCertificate() {
    return hasProxyCertificate;
  }

  public Date getProxyExpirationTime() {
    return proxyExpirationTime;
  }




  public static class Builder {

    private String display;

    private String subjectDn;

    private String issuerDn;

    private Boolean primary;

    private String pemEncodedCertificate;

    private Date created;

    private Date lastModified;
    
    private boolean hasProxyCertificate;
    
    private Date proxyExpirationTime;

    public Builder display(String display) {
      this.display = display;
      return this;
    }

    public Builder primary(Boolean primary) {

      this.primary = primary;
      return this;
    }

    public Builder subjectDn(String subjectDn) {
      this.subjectDn = subjectDn;
      return this;
    }

    public Builder issuerDn(String issuerDn) {
      this.issuerDn = issuerDn;
      return this;
    }

    public Builder created(Date created) {
      this.created = created;
      return this;
    }

    public Builder lastModified(Date lastModified) {
      this.lastModified = lastModified;
      return this;
    }

    public Builder pemEncodedCertificate(String certificate) {
      this.pemEncodedCertificate = certificate;
      return this;
    }
    
    public Builder hasProxyCertificate(boolean hasProxy) {
      this.hasProxyCertificate = hasProxy;
      return this;
    }
    
    public Builder proxyExpirationTime(Date et) {
      this.proxyExpirationTime = et;
      return this;
    }

    public ScimX509Certificate build() {
      return new ScimX509Certificate(this);
    }
  }

  public static Builder builder() {
    return new Builder();
  }
}
