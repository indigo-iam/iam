package it.infn.mw.iam.api.scim.model;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class ScimIndigoUser {

  private final List<ScimSshKey> sshKeys;
  private final List<ScimOidcId> oidcIds;
  private final List<ScimSamlId> samlIds;

  private final ScimIndigoUserInfo userInfo;
  private final Set<ScimAuthority> authorities;

  @JsonCreator
  private ScimIndigoUser(@JsonProperty("oidcIds") List<ScimOidcId> oidcIds,
      @JsonProperty("sshKeys") List<ScimSshKey> sshKeys,
      @JsonProperty("samlIds") List<ScimSamlId> samlIds,
      @JsonProperty("userInfo") ScimIndigoUserInfo userInfo,
      @JsonProperty("authorities") Set<ScimAuthority> authorities) {

    this.oidcIds = oidcIds != null ? oidcIds : new LinkedList<ScimOidcId>();
    this.sshKeys = sshKeys != null ? sshKeys : new LinkedList<ScimSshKey>();
    this.samlIds = samlIds != null ? samlIds : new LinkedList<ScimSamlId>();
    this.userInfo = userInfo;
    this.authorities = authorities;

  }

  private ScimIndigoUser(Builder b) {
    this.sshKeys = b.sshKeys;
    this.oidcIds = b.oidcIds;
    this.samlIds = b.samlIds;
    this.userInfo = b.userInfo;
    this.authorities = b.authorities;
  }

  @JsonIgnore
  public boolean isEmpty() {

    return sshKeys.isEmpty() && oidcIds.isEmpty() && samlIds.isEmpty() && authorities.isEmpty()
        && userInfo == null;
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

  public ScimIndigoUserInfo getUserInfo() {

    return userInfo;
  }

  public Set<ScimAuthority> getAuthorities() {

    return authorities;
  }

  public static Builder builder() {

    return new Builder();
  }

  public static class Builder {

    private List<ScimSshKey> sshKeys = new LinkedList<ScimSshKey>();
    private List<ScimOidcId> oidcIds = new LinkedList<ScimOidcId>();
    private List<ScimSamlId> samlIds = new LinkedList<ScimSamlId>();

    private ScimIndigoUserInfo userInfo;

    private Set<ScimAuthority> authorities = new HashSet<ScimAuthority>();

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

    public Builder indigoUserInfo(ScimIndigoUserInfo userInfo) {

      this.userInfo = userInfo;
      return this;
    }

    public Builder authorities(Set<ScimAuthority> authorities) {

      this.authorities = authorities;
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
