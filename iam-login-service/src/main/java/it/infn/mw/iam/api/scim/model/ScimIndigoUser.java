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
import java.util.LinkedList;
import java.util.List;

import javax.validation.Valid;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonFilter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.google.common.collect.Lists;

import it.infn.mw.iam.api.scim.controller.utils.JsonDateSerializer;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class ScimIndigoUser {

  public enum INDIGO_USER_SCHEMA {

    // @formatter:off
    SSH_KEYS(ScimConstants.INDIGO_USER_SCHEMA + ".sshKeys"),
    OIDC_IDS(ScimConstants.INDIGO_USER_SCHEMA + ".oidcIds"),
    SAML_IDS(ScimConstants.INDIGO_USER_SCHEMA + ".samlIds"),
    X509_CERTS(ScimConstants.INDIGO_USER_SCHEMA + ".x509Certificates"),
    AUP_SIGNATURE_TIME(ScimConstants.INDIGO_USER_SCHEMA + ".aupSignatureTime"),
    LABELS(ScimConstants.INDIGO_USER_SCHEMA + ".labels"),
    AUTHORITIES(ScimConstants.INDIGO_USER_SCHEMA + ".authorities"),
    ATTRIBUTES(ScimConstants.INDIGO_USER_SCHEMA + ".attributes"),
    MANAGED_GROUPS(ScimConstants.INDIGO_USER_SCHEMA + ".managedGroups");
    // @formatter:on

    private final String text;

    private INDIGO_USER_SCHEMA(String text) {
      this.text = text;
    }

    @Override
    public String toString() {
      return text;
    }
  }

  private final List<ScimSshKey> sshKeys;
  private final List<ScimOidcId> oidcIds;

  private final List<ScimLabel> labels;

  @Valid
  private final List<ScimSamlId> samlIds;

  @Valid
  @JsonFilter("pemEncodedCertificateFilter")
  private final List<ScimX509Certificate> certificates;

  @JsonSerialize(using = JsonDateSerializer.class)
  private final Date aupSignatureTime;

  @JsonSerialize(using = JsonDateSerializer.class)
  private final Date endTime;

  private final List<String> authorities;

  @Valid
  private final List<ScimAttribute> attributes;

  @Valid
  private final List<ScimGroupRef> managedGroups;

  private Boolean serviceAccount;
  private String affiliation;

  @JsonCreator
  private ScimIndigoUser(@JsonProperty("oidcIds") List<ScimOidcId> oidcIds,
      @JsonProperty("sshKeys") List<ScimSshKey> sshKeys,
      @JsonProperty("samlIds") List<ScimSamlId> samlIds,
      @JsonProperty("x509Certificates") List<ScimX509Certificate> certs,
      @JsonProperty("aupSignatureTime") Date aupSignatureTime,
      @JsonProperty("endTime") Date endTime, 
      @JsonProperty("serviceAccount") Boolean serviceAccount,
      @JsonProperty("affiliation") String affiliation) {

    this.oidcIds = oidcIds != null ? oidcIds : new LinkedList<>();
    this.sshKeys = sshKeys != null ? sshKeys : new LinkedList<>();
    this.samlIds = samlIds != null ? samlIds : new LinkedList<>();
    this.certificates = certs != null ? certs : new LinkedList<>();
    this.aupSignatureTime = aupSignatureTime;
    this.endTime = endTime;
    this.serviceAccount = serviceAccount;
    this.affiliation = affiliation;
    this.labels = null;
    this.authorities = null;
    this.attributes = null;
    this.managedGroups = null;
  }

  private ScimIndigoUser(Builder b) {
    this.sshKeys = b.sshKeys;
    this.oidcIds = b.oidcIds;
    this.samlIds = b.samlIds;
    this.certificates = b.certificates;
    this.aupSignatureTime = b.aupSignatureTime;
    this.endTime = b.endTime;
    this.serviceAccount = b.serviceAccount;
    this.affiliation = b.affiliation;
    this.labels = b.labels;
    this.attributes = b.attributes;
    this.managedGroups = b.managedGroups;
    this.authorities = b.authorities;
  }

  public List<ScimSshKey> getSshKeys() {

    return sshKeys;
  }

  public List<ScimOidcId> getOidcIds() {

    return oidcIds;
  }

  public List<ScimSamlId> getSamlIds() {

    return samlIds;
  }

  public List<ScimX509Certificate> getCertificates() {
    return certificates;
  }

  public Date getAupSignatureTime() {
    return aupSignatureTime;
  }

  public List<ScimLabel> getLabels() {
    return labels;
  }

  public List<String> getAuthorities() {
    return authorities;
  }

  public List<ScimAttribute> getAttributes() {
    return attributes;
  }

  public List<ScimGroupRef> getManagedGroups() {
    return managedGroups;
  }

  public Date getEndTime() {
    return endTime;
  }

  public Boolean getServiceAccount() {
    return serviceAccount;
  }

  public String getAffiliation() {
    return affiliation;
  }

  public static Builder builder() {

    return new Builder();
  }

  public static class Builder {

    private List<ScimSshKey> sshKeys = Lists.newLinkedList();
    private List<ScimOidcId> oidcIds = Lists.newLinkedList();
    private List<ScimSamlId> samlIds = Lists.newLinkedList();
    private List<ScimX509Certificate> certificates = Lists.newLinkedList();
    private List<ScimLabel> labels = Lists.newLinkedList();

    private Date aupSignatureTime;
    private Date endTime;
    private Boolean serviceAccount;
    private String affiliation;

    private List<String> authorities = Lists.newLinkedList();
    private List<ScimAttribute> attributes = Lists.newLinkedList();
    private List<ScimGroupRef> managedGroups = Lists.newLinkedList();

    public Builder addSshKey(ScimSshKey sshKey) {

      sshKeys.add(sshKey);
      return this;
    }

    public Builder addOidcId(ScimOidcId oidcId) {

      oidcIds.add(oidcId);
      return this;
    }

    public Builder addSamlId(ScimSamlId samlId) {

      samlIds.add(samlId);
      return this;
    }

    public Builder addCertificate(ScimX509Certificate cert) {
      certificates.add(cert);
      return this;
    }

    public Builder aupSignatureTime(Date signatureTime) {
      this.aupSignatureTime = signatureTime;
      return this;
    }

    public Builder endTime(Date endTime) {
      this.endTime = endTime;
      return this;
    }

    public Builder serviceAccount(Boolean serviceAccount) {
      this.serviceAccount = serviceAccount;
      return this;
    }

    public Builder affiliation(String affiliation) {
      this.affiliation = affiliation;
      return this;
    }

    public Builder labels(List<ScimLabel> labels) {
      this.labels = labels;
      return this;
    }

    public Builder addLabel(ScimLabel label) {
      labels.add(label);
      return this;
    }

    public Builder addAuthority(String authority) {
      authorities.add(authority);
      return this;
    }

    public Builder addAttribute(ScimAttribute attribute) {
      attributes.add(attribute);
      return this;
    }

    public Builder addManagedGroup(ScimGroupRef groupRef) {
      managedGroups.add(groupRef);
      return this;
    }

    public ScimIndigoUser build() {
      return new ScimIndigoUser(this);
    }

  }

}
