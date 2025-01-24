package it.infn.mw.iam.persistence.model;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import javax.persistence.Basic;
import javax.persistence.CollectionTable;
import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.MapKeyColumn;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import it.infn.mw.iam.persistence.model.converter.SimpleGrantedAuthorityStringConverter;

@Entity
@Table(name = "saved_user_auth")
public class SavedUserAuthentication implements Authentication {

  private static final long serialVersionUID = -1804249963940323488L;

  private Long id;

  private String name;

  private Collection<GrantedAuthority> authorities;

  private boolean authenticated;

  private String sourceClass;

  private Map<String, String> additionalInfo = new HashMap<>();

  public SavedUserAuthentication(Authentication src) {
    setName(src.getName());
    setAuthorities(src.getAuthorities());
    setAuthenticated(src.isAuthenticated());

    if (src instanceof SavedUserAuthentication) {
      setSourceClass(((SavedUserAuthentication) src).getSourceClass());
      additionalInfo.putAll(((SavedUserAuthentication) src).getAdditionalInfo());
    } else {
      setSourceClass(src.getClass().getName());
    }
  }

  public SavedUserAuthentication() {
    // Empty Constructor
  }

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "id")
  public Long getId() {
    return id;
  }

  /**
   * @param id the id to set
   */
  public void setId(Long id) {
    this.id = id;
  }

  @Override
  @Basic
  @Column(name = "name")
  public String getName() {
    return name;
  }

  @Override
  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "saved_user_auth_authority",
      joinColumns = @JoinColumn(name = "owner_id") )
  @Convert(converter = SimpleGrantedAuthorityStringConverter.class)
  @Column(name = "authority")
  public Collection<GrantedAuthority> getAuthorities() {
    return authorities;
  }

  @Override
  @Transient
  public Object getCredentials() {
    return "";
  }

  @Override
  @Transient
  public Object getDetails() {
    return null;
  }

  @Override
  @Transient
  public Object getPrincipal() {
    return getName();
  }

  @Override
  @Basic
  @Column(name = "authenticated")
  public boolean isAuthenticated() {
    return authenticated;
  }

  @Override
  public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
    this.authenticated = isAuthenticated;
  }

  @Basic
  @Column(name = "source_class")
  public String getSourceClass() {
    return sourceClass;
  }

  public void setSourceClass(String sourceClass) {
    this.sourceClass = sourceClass;
  }

  public void setName(String name) {
    this.name = name;
  }

  public void setAuthorities(Collection<? extends GrantedAuthority> authorities) {
    if (authorities != null) {
      this.authorities = new HashSet<>(authorities);
    } else {
      this.authorities = null;
    }
  }

  @ElementCollection(fetch = FetchType.EAGER)
  @MapKeyColumn(name = "info_key")
  @Column(name = "info_val", length = 256)
  @CollectionTable(name = "saved_user_auth_info", joinColumns = @JoinColumn(name = "owner_id") )
  public Map<String, String> getAdditionalInfo() {
    return additionalInfo;
  }

  public void setAdditionalInfo(Map<String, String> additionalInfo) {
    this.additionalInfo = additionalInfo;
  }
}
