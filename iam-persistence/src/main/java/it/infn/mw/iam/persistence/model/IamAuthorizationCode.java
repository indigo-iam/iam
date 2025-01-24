package it.infn.mw.iam.persistence.model;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.Basic;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;
import javax.persistence.Temporal;

@Entity
@Table(name = "authorization_code")
@NamedQueries({
    @NamedQuery(name = IamAuthorizationCode.QUERY_BY_VALUE,
        query = "select a from IamAuthorizationCode a where a.code = :code"),
    @NamedQuery(name = IamAuthorizationCode.QUERY_EXPIRATION_BY_DATE,
        query = "select a from IamAuthorizationCode a where a.expiration <= :"
            + IamAuthorizationCode.PARAM_DATE),
    @NamedQuery(name = IamAuthorizationCode.QUERY_DELETE_EXPIRED,
        query = "DELETE FROM IamAuthorizationCode a WHERE a.expiration <= :"
            + IamAuthorizationCode.PARAM_DATE)})
public class IamAuthorizationCode implements Serializable {

  private static final long serialVersionUID = 1L;

  public static final String QUERY_BY_VALUE = "IamAuthorizationCode.getByValue";
  public static final String QUERY_EXPIRATION_BY_DATE = "IamAuthorizationCode.expirationByDate";
  public static final String QUERY_DELETE_EXPIRED = "IamAuthorizationCode.deleteExpired";

  public static final String PARAM_DATE = "date";

  private Long id;

  private String code;

  private IamAuthenticationHolder authenticationHolder;

  private Date expiration;

  public IamAuthorizationCode() {
    // Empty Constructor
  }

  /**
   * Create a new AuthorizationCodeEntity with the given code and AuthorizationRequestHolder.
   *
   * @param code the authorization code
   * @param authRequest the AuthoriztionRequestHolder associated with the original code request
   */
  public IamAuthorizationCode(String code, IamAuthenticationHolder authenticationHolder,
      Date expiration) {
    this.code = code;
    this.authenticationHolder = authenticationHolder;
    this.expiration = expiration;
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

  @Basic
  @Column(name = "code")
  public String getCode() {
    return code;
  }

  public void setCode(String code) {
    this.code = code;
  }

  @ManyToOne
  @JoinColumn(name = "auth_holder_id")
  public IamAuthenticationHolder getAuthenticationHolder() {
    return authenticationHolder;
  }

  public void setAuthenticationHolder(IamAuthenticationHolder authenticationHolder) {
    this.authenticationHolder = authenticationHolder;
  }

  @Basic
  @Temporal(javax.persistence.TemporalType.TIMESTAMP)
  @Column(name = "expiration")
  public Date getExpiration() {
    return expiration;
  }

  public void setExpiration(Date expiration) {
    this.expiration = expiration;
  }
}
