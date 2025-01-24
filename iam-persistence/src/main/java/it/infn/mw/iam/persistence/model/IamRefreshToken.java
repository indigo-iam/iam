package it.infn.mw.iam.persistence.model;

import java.util.Date;

import javax.persistence.Basic;
import javax.persistence.Column;
import javax.persistence.Convert;
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

import org.springframework.security.oauth2.common.OAuth2RefreshToken;

import com.nimbusds.jwt.JWT;

import it.infn.mw.iam.persistence.model.converter.JWTStringConverter;

@SuppressWarnings("deprecation")
@Entity
@Table(name = "refresh_token")
@NamedQueries({
    @NamedQuery(name = IamRefreshToken.QUERY_ALL, query = "select r from IamRefreshToken r"),
    @NamedQuery(name = IamRefreshToken.QUERY_EXPIRED_BY_DATE,
        query = "select r from IamRefreshToken r where r.expiration <= :"
            + IamRefreshToken.PARAM_DATE),
    @NamedQuery(name = IamRefreshToken.QUERY_BY_CLIENT,
        query = "select r from IamRefreshToken r where r.client = :"
            + IamRefreshToken.PARAM_CLIENT),
    @NamedQuery(name = IamRefreshToken.QUERY_BY_TOKEN_VALUE,
        query = "select r from IamRefreshToken r where r.jwt = :"
            + IamRefreshToken.PARAM_TOKEN_VALUE),
    @NamedQuery(name = IamRefreshToken.QUERY_BY_NAME,
        query = "select r from IamRefreshToken r where r.authenticationHolder.userAuth.name = :"
            + IamRefreshToken.PARAM_NAME)})
public class IamRefreshToken implements OAuth2RefreshToken {

  public static final String QUERY_BY_TOKEN_VALUE = "IamRefreshToken.getByTokenValue";
  public static final String QUERY_BY_CLIENT = "IamRefreshToken.getByClient";
  public static final String QUERY_EXPIRED_BY_DATE = "IamRefreshToken.getAllExpiredByDate";
  public static final String QUERY_ALL = "IamRefreshToken.getAll";
  public static final String QUERY_BY_NAME = "IamRefreshToken.getByName";

  public static final String PARAM_TOKEN_VALUE = "tokenValue";
  public static final String PARAM_CLIENT = "client";
  public static final String PARAM_DATE = "date";
  public static final String PARAM_NAME = "name";

  private Long id;

  private IamAuthenticationHolder authenticationHolder;

  private IamClient client;

  // JWT-encoded representation of this access token entity
  private JWT jwt;

  // our refresh tokens might expire
  private Date expiration;

  public IamRefreshToken() {
    // Empty Constructor
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

  @ManyToOne
  @JoinColumn(name = "auth_holder_id")
  public IamAuthenticationHolder getAuthenticationHolder() {
    return authenticationHolder;
  }

  public void setAuthenticationHolder(IamAuthenticationHolder authenticationHolder) {
    this.authenticationHolder = authenticationHolder;
  }

  @Override
  @Transient
  public String getValue() {
    return jwt.serialize();
  }

  @Basic
  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "expiration")
  public Date getExpiration() {
    return expiration;
  }

  public void setExpiration(Date expiration) {
    this.expiration = expiration;
  }

  @Transient
  public boolean isExpired() {
    return getExpiration() == null ? false : System.currentTimeMillis() > getExpiration().getTime();
  }

  @ManyToOne(fetch = FetchType.EAGER)
  @JoinColumn(name = "client_id")
  public IamClient getClient() {
    return client;
  }

  public void setClient(IamClient client) {
    this.client = client;
  }

  @Basic
  @Column(name = "token_value")
  @Convert(converter = JWTStringConverter.class)
  public JWT getJwt() {
    return jwt;
  }

  public void setJwt(JWT jwt) {
    this.jwt = jwt;
  }

}
