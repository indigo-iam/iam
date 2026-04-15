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

import java.util.LinkedList;
import java.util.List;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class ScimAarcUser {

  public enum AARC_USER_SCHEMA {

    // @formatter:off
    VOPERSON_ID(ScimConstants.AARC_USER_SCHEMA + ".voPersonId"),
    ORGANIZATION_NAME(ScimConstants.AARC_USER_SCHEMA + ".organizationName"),
    SCHAC_HOME_ORGANIZATION(ScimConstants.AARC_USER_SCHEMA + ".schacHomeOrganization"),
    VO_PERSON_EXTERNAL_AFFILIATIONS(ScimConstants.AARC_USER_SCHEMA + ".voPersonExternalAffiliations"),
    ASSURANCE(ScimConstants.AARC_USER_SCHEMA + ".assurance"),
    ENTITLEMENTS(ScimConstants.AARC_USER_SCHEMA + ".entitlements");
    // @formatter:on

    private final String text;

    AARC_USER_SCHEMA(String text) {
      this.text = text;
    }

    @Override
    public String toString() {
      return text;
    }
  }

  @NotNull
  private final String voPersonId;

  private final String organizationName;

  private final String schacHomeOrganization;

  @NotNull
  private final List<ScimAffiliation> voPersonExternalAffiliations;

  @Valid
  private final List<ScimAssurance> assurance;

  @Valid
  private final List<ScimEntitlement> entitlements;

  @JsonCreator
  private ScimAarcUser(@JsonProperty("voPersonId") String voPersonId,
      @JsonProperty("organizationName") String organizationName,
      @JsonProperty("schacHomeOrganization") String schacHomeOrganization,
      @JsonProperty("voPersonExternalAffiliations") List<ScimAffiliation> voPersonExternalAffiliations,
      @JsonProperty("assurance") List<ScimAssurance> assurance,
      @JsonProperty("entitlements") List<ScimEntitlement> entitlements) {

    this.voPersonId = voPersonId;
    this.organizationName = organizationName;
    this.schacHomeOrganization = schacHomeOrganization;
    this.voPersonExternalAffiliations = voPersonExternalAffiliations;
    this.assurance = assurance != null ? assurance : new LinkedList<>();
    this.entitlements = entitlements != null ? entitlements : new LinkedList<>();
  }

  private ScimAarcUser(Builder b) {
    this.voPersonId = b.voPersonId;
    this.organizationName = b.organizationName;
    this.schacHomeOrganization = b.schacHomeOrganization;
    this.voPersonExternalAffiliations = b.voPersonExternalAffiliations;
    this.assurance = b.assurance;
    this.entitlements = b.entitlements;
  }

  public String getVoPersonId() {
    return voPersonId;
  }

  public String getOrganizationName() {
    return organizationName;
  }

  public String getSchacHomeOrganization() {
    return schacHomeOrganization;
  }

  public List<ScimAffiliation> getVoPersonExternalAffiliations() {
    return voPersonExternalAffiliations;
  }

  public List<ScimAssurance> getAssurance() {
    return assurance;
  }

  public List<ScimEntitlement> getEntitlements() {
    return entitlements;
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {

    private String voPersonId;

    private String organizationName;
    private String schacHomeOrganization;
    private List<ScimAffiliation> voPersonExternalAffiliations;
    private List<ScimAssurance> assurance = new LinkedList<>();
    private List<ScimEntitlement> entitlements = new LinkedList<>();

    public Builder voPersonId(String voPersonId) {
      this.voPersonId = voPersonId;
      return this;
    }

    public Builder organizationName(String organizationName) {
      this.organizationName = organizationName;
      return this;
    }

    public Builder schacHomeOrganization(String schacHomeOrganization) {
      this.schacHomeOrganization = schacHomeOrganization;
      return this;
    }

    public Builder voPersonExternalAffiliation(ScimAffiliation affiliation) {
      this.voPersonExternalAffiliations.add(affiliation);
      return this;
    }

    public Builder addAssurance(ScimAssurance assurance) {
      this.assurance.add(assurance);
      return this;
    }

    public Builder addEntitlement(ScimEntitlement entitlement) {
      this.entitlements.add(entitlement);
      return this;
    }

    public ScimAarcUser build() {
      return new ScimAarcUser(this);
    }
  }
}
