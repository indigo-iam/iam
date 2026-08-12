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

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

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

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "id")
  private Long id;

  @Column(name = "name")
  private String name;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "saved_user_auth_authority", joinColumns = @JoinColumn(name = "owner_id"))
  @Convert(converter = SimpleGrantedAuthorityStringConverter.class)
  @Column(name = "authority")
  private Collection<GrantedAuthority> authorities;

  @Column(name = "authenticated")
  private boolean authenticated;

  @Column(name = "source_class")
  private String sourceClass;

  @ElementCollection(fetch = FetchType.EAGER)
  @MapKeyColumn(name = "info_key")
  @Column(name = "info_val", length = 512)
  @CollectionTable(name = "saved_user_auth_info", joinColumns = @JoinColumn(name = "owner_id"))
  private Map<String, String> additionalInfo = new HashMap<>();

  public SavedUserAuthentication(Authentication src) {

    setName(src.getName());
    setAuthorities(src.getAuthorities());
    setAuthenticated(src.isAuthenticated());

    if (src instanceof SavedUserAuthentication sua) {

      setSourceClass(sua.getSourceClass());
      additionalInfo.putAll(sua.getAdditionalInfo());

    } else {

      setSourceClass(src.getClass().getName());

    }

    if (src.getDetails() instanceof Map<?,?> details) {

      Object acr = details.get("acr");
      if (acr != null) {
        additionalInfo.put("acr", acr.toString());
      }

    }
  }

  public SavedUserAuthentication() {

  }

  public Long getId() {

    return id;
  }

  public void setId(Long id) {

    this.id = id;
  }

  @Override
  public String getName() {

    return name;
  }

  @Override
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
  public boolean isAuthenticated() {

    return authenticated;
  }

  @Override
  public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {

    this.authenticated = isAuthenticated;
  }

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

    this.authorities = authorities != null ? new HashSet<>(authorities) : null;
  }

  public Map<String, String> getAdditionalInfo() {

    return additionalInfo;
  }

  public void setAdditionalInfo(Map<String, String> additionalInfo) {

    this.additionalInfo = additionalInfo;
  }
}
