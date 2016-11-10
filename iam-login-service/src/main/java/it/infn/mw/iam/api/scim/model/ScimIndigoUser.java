package it.infn.mw.iam.api.scim.model;

import java.util.LinkedList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class ScimIndigoUser {

  private final List<ScimSshKey> sshKeys;
  private final List<ScimOidcId> oidcIds;
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

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((oidcIds == null) ? 0 : oidcIds.hashCode());
    result = prime * result + ((samlIds == null) ? 0 : samlIds.hashCode());
    result = prime * result + ((sshKeys == null) ? 0 : sshKeys.hashCode());
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    ScimIndigoUser other = (ScimIndigoUser) obj;
    if (oidcIds == null) {
      if (other.oidcIds != null)
        return false;
    } else if (!oidcIds.equals(other.oidcIds))
      return false;
    if (samlIds == null) {
      if (other.samlIds != null)
        return false;
    } else if (!samlIds.equals(other.samlIds))
      return false;
    if (sshKeys == null) {
      if (other.sshKeys != null)
        return false;
    } else if (!sshKeys.equals(other.sshKeys))
      return false;
    return true;
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

    public Builder buildOidcId(String issuer, String subject) {

      oidcIds.add(ScimOidcId.builder().subject(subject).issuer(issuer).build());
      return this;
    }

    public Builder buildSshKey(String label, String key, String fingerprint, boolean isPrimary) {

      sshKeys.add(ScimSshKey.builder()
        .display(label)
        .value(key)
        .fingerprint(fingerprint)
        .primary(isPrimary)
        .build());
      return this;
    }

    public Builder buildSamlId(String idpId, String userId) {

      samlIds.add(ScimSamlId.builder().idpId(idpId).userId(userId).build());
      return this;
    }

    public ScimIndigoUser build() {

      return new ScimIndigoUser(this);
    }
  }

}
