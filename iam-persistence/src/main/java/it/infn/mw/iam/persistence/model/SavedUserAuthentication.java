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
package it.infn.mw.iam.persistence.model;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

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

import it.infn.mw.iam.persistence.model.convert.SimpleGrantedAuthorityStringConverter;

@Entity
@Table(name = "saved_user_auth")
public class SavedUserAuthentication implements Authentication {

  private static final long serialVersionUID = -1804249963940323488L;

  private Long id;

  private String name;

  private Set<GrantedAuthority> authorities = new HashSet<>();

  private boolean authenticated;

  private String sourceClass;

  private Map<String, String> additionalInfo = new HashMap<>();

  public SavedUserAuthentication(Authentication src) {
    setName(src.getName());
    setAuthorities(new HashSet<>(src.getAuthorities()));
    setAuthenticated(src.isAuthenticated());

    if (src instanceof SavedUserAuthentication) {
      // if we're copying in a saved auth, carry over the original class name
      setSourceClass(((SavedUserAuthentication) src).getSourceClass());
      additionalInfo.putAll(((SavedUserAuthentication) src).getAdditionalInfo());

    } else {
      setSourceClass(src.getClass().getName());
    }

    if (src.getDetails() instanceof Map<?, ?>) {
      Map<?, ?> details = (Map<?, ?>) src.getDetails();
      Object acr = details.get("acr");
      if (acr != null) {
        additionalInfo.put("acr", acr.toString());
      }
    }
  }

  public SavedUserAuthentication() {

  }

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "id")
  public Long getId() {
    return id;
  }

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
  @CollectionTable(name = "saved_user_auth_authority", joinColumns = @JoinColumn(name = "owner_id"))
  @Convert(converter = SimpleGrantedAuthorityStringConverter.class)
  @Column(name = "authority")
  public Set<GrantedAuthority> getAuthorities() {
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

  public void setAuthorities(Set<? extends GrantedAuthority> authorities) {
    Objects.nonNull(authorities);
    this.authorities.clear();
    this.authorities = new HashSet<>();
    this.authorities.addAll(authorities);
  }

  @ElementCollection(fetch = FetchType.EAGER)
  @MapKeyColumn(name = "info_key")
  @Column(name = "info_val", length = 256)
  @CollectionTable(name = "saved_user_auth_info", joinColumns = @JoinColumn(name = "owner_id"))
  public Map<String, String> getAdditionalInfo() {
    return additionalInfo;
  }

  public void setAdditionalInfo(Map<String, String> additionalInfo) {
    this.additionalInfo = additionalInfo;
  }
}
