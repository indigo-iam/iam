package it.infn.mw.iam.persistence.model;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.persistence.CascadeType;
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
import javax.persistence.OneToOne;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import it.infn.mw.iam.persistence.model.converter.SerializableStringConverter;
import it.infn.mw.iam.persistence.model.converter.SimpleGrantedAuthorityStringConverter;

@SuppressWarnings("deprecation")
@Entity
@Table(name = "authentication_holder")
public class AuthenticationHolder {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "id")
  private Long id;

  @OneToOne(cascade = CascadeType.ALL)
  @JoinColumn(name = "user_auth_id")
  private SavedUserAuthentication userAuth;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "authentication_holder_authority",
      joinColumns = @JoinColumn(name = "owner_id"))
  @Convert(converter = SimpleGrantedAuthorityStringConverter.class)
  @Column(name = "authority")
  private Collection<GrantedAuthority> authorities;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "authentication_holder_resource_id",
      joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "resource_id")
  private Set<String> resourceIds;

  @Column(name = "approved")
  private boolean approved;

  @Column(name = "redirect_uri")
  private String redirectUri;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "authentication_holder_response_type",
      joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "response_type")
  private Set<String> responseTypes;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "authentication_holder_extension",
      joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "val")
  @MapKeyColumn(name = "extension")
  @Convert(converter = SerializableStringConverter.class)
  private Map<String, Serializable> extensions;

  @Column(name = "client_id")
  private String clientId;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "authentication_holder_scope",
      joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "scope")
  private Set<String> scope;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "authentication_holder_request_parameter",
      joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "val")
  @MapKeyColumn(name = "param")
  private Map<String, String> requestParameters;


  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public SavedUserAuthentication getUserAuth() {
    return userAuth;
  }

  public void setUserAuth(SavedUserAuthentication userAuth) {
    this.userAuth = userAuth;
  }

  public Collection<GrantedAuthority> getAuthorities() {
    return authorities;
  }

  public void setAuthorities(Collection<GrantedAuthority> authorities) {
    this.authorities = authorities;
  }

  public Set<String> getResourceIds() {
    return resourceIds;
  }

  public void setResourceIds(Set<String> resourceIds) {
    this.resourceIds = resourceIds;
  }

  public boolean isApproved() {
    return approved;
  }

  public void setApproved(boolean approved) {
    this.approved = approved;
  }

  public String getRedirectUri() {
    return redirectUri;
  }

  public void setRedirectUri(String redirectUri) {
    this.redirectUri = redirectUri;
  }

  public Set<String> getResponseTypes() {
    return responseTypes;
  }

  public void setResponseTypes(Set<String> responseTypes) {
    this.responseTypes = responseTypes;
  }

  public Map<String, Serializable> getExtensions() {
    return extensions;
  }

  public void setExtensions(Map<String, Serializable> extensions) {
    this.extensions = extensions;
  }

  public String getClientId() {
    return clientId;
  }

  public void setClientId(String clientId) {
    this.clientId = clientId;
  }

  public Set<String> getScope() {
    return scope;
  }

  public void setScope(Set<String> scope) {
    this.scope = scope;
  }

  public Map<String, String> getRequestParameters() {
    return requestParameters;
  }

  public void setRequestParameters(Map<String, String> requestParameters) {
    this.requestParameters = requestParameters;
  }

  @Transient
  public OAuth2Authentication getAuthentication() {
    return new OAuth2Authentication(createOAuth2Request(), getUserAuth());
  }

  private OAuth2Request createOAuth2Request() {
    return new OAuth2Request(requestParameters, clientId, authorities, approved, scope, resourceIds,
        redirectUri, responseTypes, extensions);
  }

  public void setAuthentication(OAuth2Authentication authentication) {

    // pull apart the request and save its bits
    OAuth2Request o2Request = authentication.getOAuth2Request();
    setAuthorities(
        o2Request.getAuthorities() == null ? null : new HashSet<>(o2Request.getAuthorities()));
    setClientId(o2Request.getClientId());
    setExtensions(
        o2Request.getExtensions() == null ? null : new HashMap<>(o2Request.getExtensions()));
    setRedirectUri(o2Request.getRedirectUri());
    setRequestParameters(o2Request.getRequestParameters() == null ? null
        : new HashMap<>(o2Request.getRequestParameters()));
    setResourceIds(
        o2Request.getResourceIds() == null ? null : new HashSet<>(o2Request.getResourceIds()));
    setResponseTypes(
        o2Request.getResponseTypes() == null ? null : new HashSet<>(o2Request.getResponseTypes()));
    setScope(o2Request.getScope() == null ? null : new HashSet<>(o2Request.getScope()));
    setApproved(o2Request.isApproved());

    if (authentication.getUserAuthentication() != null) {
      this.userAuth = new SavedUserAuthentication(authentication.getUserAuthentication());
    } else {
      this.userAuth = null;
    }
  }
}
