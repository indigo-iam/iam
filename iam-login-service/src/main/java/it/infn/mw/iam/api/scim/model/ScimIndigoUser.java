package it.infn.mw.iam.api.scim.model;

import java.util.LinkedList;
import java.util.List;

import javax.validation.Valid;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class ScimIndigoUser {

  public enum INDIGO_USER_SCHEMA {

    SSH_KEYS(ScimConstants.INDIGO_USER_SCHEMA + ".sshKeys"),
    OIDC_IDS(ScimConstants.INDIGO_USER_SCHEMA + ".oidcIds"),
    SAML_IDS(ScimConstants.INDIGO_USER_SCHEMA + ".samlIds");

    private final String text;

    private INDIGO_USER_SCHEMA(String text) {
      this.text = text;
    }

    @Override
    public String toString() {
      return text;
    }
  };

  private final List<ScimSshKey> sshKeys;
  private final List<ScimOidcId> oidcIds;
  
  @Valid
  private final List<ScimSamlId> samlIds;

  @JsonCreator
  private ScimIndigoUser(@JsonProperty("oidcIds") List<ScimOidcId> oidcIds,
      @JsonProperty("sshKeys") List<ScimSshKey> sshKeys,
      @JsonProperty("samlIds") List<ScimSamlId> samlIds) {

    this.oidcIds = oidcIds != null ? oidcIds : new LinkedList<ScimOidcId>();
    this.sshKeys = sshKeys != null ? sshKeys : new LinkedList<ScimSshKey>();
    this.samlIds = samlIds != null ? samlIds : new LinkedList<ScimSamlId>();

  }

  private ScimIndigoUser(Builder b) {
    this.sshKeys = b.sshKeys;
    this.oidcIds = b.oidcIds;
    this.samlIds = b.samlIds;
  }

  @JsonIgnore
  public boolean isEmpty() {

    return sshKeys.isEmpty() && oidcIds.isEmpty() && samlIds.isEmpty();
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

  public static Builder builder() {

    return new Builder();
  }

  public static class Builder {

    private List<ScimSshKey> sshKeys = new LinkedList<ScimSshKey>();
    private List<ScimOidcId> oidcIds = new LinkedList<ScimOidcId>();
    private List<ScimSamlId> samlIds = new LinkedList<ScimSamlId>();

    public Builder addSshKey(ScimSshKey sshKey) {

      sshKeys.add(sshKey);
      return this;
    }

    public Builder addOidcid(ScimOidcId oidcId) {

      oidcIds.add(oidcId);
      return this;
    }

    public Builder addSamlId(ScimSamlId samlId) {

      samlIds.add(samlId);
      return this;
    }

    public ScimIndigoUser build() {

      return new ScimIndigoUser(this);
    }
  }

}
