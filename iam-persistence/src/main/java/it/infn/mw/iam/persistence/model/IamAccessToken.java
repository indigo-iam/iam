package it.infn.mw.iam.persistence.model;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
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
import javax.persistence.ManyToOne;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.persistence.Transient;

import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessTokenJackson2Deserializer;
import org.springframework.security.oauth2.common.OAuth2AccessTokenJackson2Serializer;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;

import com.google.common.hash.Hashing;
import com.nimbusds.jwt.JWT;

import it.infn.mw.iam.persistence.model.converter.JWTStringConverter;

@SuppressWarnings("deprecation")
@Entity
@Table(name = "access_token")
@NamedQueries({
    @NamedQuery(name = IamAccessToken.QUERY_ALL, query = "select a from IamAccessToken a"),
    @NamedQuery(name = IamAccessToken.QUERY_EXPIRED_BY_DATE,
        query = "select a from IamAccessToken a where a.expiration <= :"
            + IamAccessToken.PARAM_DATE),
    @NamedQuery(name = IamAccessToken.QUERY_BY_REFRESH_TOKEN,
        query = "select a from IamAccessToken a where a.refreshToken = :"
            + IamAccessToken.PARAM_REFRESH_TOKEN),
    @NamedQuery(name = IamAccessToken.QUERY_BY_CLIENT,
        query = "select a from IamAccessToken a where a.client = :" + IamAccessToken.PARAM_CLIENT),
    @NamedQuery(name = IamAccessToken.QUERY_BY_TOKEN_VALUE_HASH,
        query = "select a from IamAccessToken a where a.tokenValueHash = :"
            + IamAccessToken.PARAM_TOKEN_VALUE_HASH),
    @NamedQuery(name = IamAccessToken.QUERY_BY_APPROVED_SITE,
        query = "select a from IamAccessToken a where a.approvedSite = :"
            + IamAccessToken.PARAM_APPROVED_SITE),
    @NamedQuery(name = IamAccessToken.QUERY_BY_NAME,
        query = "select r from IamAccessToken r where r.authenticationHolder.userAuth.name = :"
            + IamAccessToken.PARAM_NAME),
    @NamedQuery(name = IamAccessToken.DELETE_BY_REFRESH_TOKEN,
        query = "delete from IamAccessToken a where a.refreshToken = :"
            + IamAccessToken.PARAM_REFRESH_TOKEN)})
@com.fasterxml.jackson.databind.annotation.JsonSerialize(
    using = OAuth2AccessTokenJackson2Serializer.class)
@com.fasterxml.jackson.databind.annotation.JsonDeserialize(
    using = OAuth2AccessTokenJackson2Deserializer.class)
public class IamAccessToken implements OAuth2AccessToken {

  public static final String QUERY_BY_APPROVED_SITE = "IamAccessToken.getByApprovedSite";
  public static final String QUERY_BY_TOKEN_VALUE_HASH = "IamAccessToken.getByTokenValue";
  public static final String QUERY_BY_CLIENT = "IamAccessToken.getByClient";
  public static final String QUERY_BY_REFRESH_TOKEN = "IamAccessToken.getByRefreshToken";
  public static final String QUERY_EXPIRED_BY_DATE = "IamAccessToken.getAllExpiredByDate";
  public static final String QUERY_ALL = "IamAccessToken.getAll";
  public static final String QUERY_BY_NAME = "IamAccessToken.getByName";
  public static final String DELETE_BY_REFRESH_TOKEN = "IamAccessToken.deleteByRefreshToken";

  public static final String PARAM_TOKEN_VALUE_HASH = "tokenValueHash";
  public static final String PARAM_CLIENT = "client";
  public static final String PARAM_REFRESH_TOKEN = "refreshToken";
  public static final String PARAM_DATE = "date";
  public static final String PARAM_RESOURCE_SET_ID = "rsid";
  public static final String PARAM_APPROVED_SITE = "approvedSite";
  public static final String PARAM_NAME = "name";

  public static final String ID_TOKEN_FIELD_NAME = "id_token";

  private Long id;

  private IamClient client;

  private IamAuthenticationHolder authenticationHolder; // the authentication that made this access

  private JWT jwtValue; // JWT-encoded access token value

  private String tokenValueHash; // hash of access token value

  private Date expiration;

  private String tokenType = OAuth2AccessToken.BEARER_TYPE;

  private IamRefreshToken refreshToken;

  private Set<String> scope;

  private IamApprovedSite approvedSite;

  private Map<String, Object> additionalInformation = new HashMap<>(); // ephemeral map of items to
                                                                       // be added to the OAuth
                                                                       // token response

  public IamAccessToken() {
    // Empty Constructor
  }

  /**
   * @return the id
   */
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

  /**
   * Get all additional information to be sent to the serializer as part of the token response. This
   * map is not persisted to the database.
   */
  @Override
  @Transient
  public Map<String, Object> getAdditionalInformation() {
    return additionalInformation;
  }

  /**
   * The authentication in place when this token was created.
   * 
   * @return the authentication
   */
  @ManyToOne
  @JoinColumn(name = "auth_holder_id")
  public IamAuthenticationHolder getAuthenticationHolder() {
    return authenticationHolder;
  }

  /**
   * @param authentication the authentication to set
   */
  public void setAuthenticationHolder(IamAuthenticationHolder authenticationHolder) {
    this.authenticationHolder = authenticationHolder;
  }

  /**
   * @return the client
   */
  @ManyToOne
  @JoinColumn(name = "client_id")
  public IamClient getClient() {
    return client;
  }

  /**
   * @param client the client to set
   */
  public void setClient(IamClient client) {
    this.client = client;
  }

  /**
   * Get the string-encoded value of this access token.
   */
  @Override
  @Transient
  public String getValue() {
    return jwtValue.serialize();
  }

  @Override
  @Basic
  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "expiration")
  public Date getExpiration() {
    return expiration;
  }

  public void setExpiration(Date expiration) {
    this.expiration = expiration;
  }

  @Override
  @Basic
  @Column(name = "token_type")
  public String getTokenType() {
    return tokenType;
  }

  public void setTokenType(String tokenType) {
    this.tokenType = tokenType;
  }

  @Override
  @ManyToOne
  @JoinColumn(name = "refresh_token_id")
  public IamRefreshToken getRefreshToken() {
    return refreshToken;
  }

  public void setRefreshToken(IamRefreshToken refreshToken) {
    this.refreshToken = refreshToken;
  }

  public void setRefreshToken(OAuth2RefreshToken refreshToken) {
    if (!(refreshToken instanceof IamRefreshToken)) {
      throw new IllegalArgumentException("Not a storable refresh token entity!");
    }
    // force a pass through to the entity version
    setRefreshToken((IamRefreshToken) refreshToken);
  }

  @Override
  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(joinColumns = @JoinColumn(name = "owner_id"), name = "token_scope")
  public Set<String> getScope() {
    return scope;
  }

  public void setScope(Set<String> scope) {
    this.scope = scope;
  }

  @Override
  @Transient
  public boolean isExpired() {
    return getExpiration() == null ? false : System.currentTimeMillis() > getExpiration().getTime();
  }

  /**
   * @return the jwtValue
   */
  @Basic
  @Column(name = "token_value")
  @Convert(converter = JWTStringConverter.class)
  public JWT getJwt() {
    return jwtValue;
  }

  /**
   * @param jwtValue the jwtValue to set
   */
  public void setJwt(JWT jwt) {
    this.jwtValue = jwt;
  }

  /**
   * @return the tokenValueHash
   */
  @Basic
  @Column(name = "token_value_hash", length = 64)
  public String getTokenValueHash() {
    return tokenValueHash;
  }

  public void setTokenValueHash(String hash) {
    this.tokenValueHash = hash;
  }

  @Override
  @Transient
  public int getExpiresIn() {

    if (getExpiration() == null) {
      return -1; // no expiration time
    } else {
      int secondsRemaining =
          (int) ((getExpiration().getTime() - System.currentTimeMillis()) / 1000);
      if (isExpired()) {
        return 0; // has an expiration time and expired
      } else { // has an expiration time and not expired
        return secondsRemaining;
      }
    }
  }

  @ManyToOne
  @JoinColumn(name = "approved_site_id")
  public IamApprovedSite getApprovedSite() {
    return approvedSite;
  }

  public void setApprovedSite(IamApprovedSite approvedSite) {
    this.approvedSite = approvedSite;
  }

  /**
   * Add the ID Token to the additionalInformation map for a token response.
   * 
   * @param idToken
   */
  @Transient
  public void setIdToken(JWT idToken) {
    if (idToken != null) {
      additionalInformation.put(ID_TOKEN_FIELD_NAME, idToken.serialize());
    }
  }

  public void hashMe() {
    if (jwtValue != null) {
      this.tokenValueHash =
          Hashing.sha256().hashString(jwtValue.serialize(), StandardCharsets.UTF_8).toString();
    }
  }
}
