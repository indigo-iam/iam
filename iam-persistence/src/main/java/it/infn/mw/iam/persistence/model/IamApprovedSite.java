package it.infn.mw.iam.persistence.model;


import java.util.Date;
import java.util.Set;

import javax.persistence.Basic;
import javax.persistence.CollectionTable;
import javax.persistence.Column;
import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.persistence.Transient;

@Entity
@Table(name = "approved_site")
@NamedQueries({
    @NamedQuery(name = IamApprovedSite.QUERY_ALL, query = "select a from IamApprovedSite a"),
    @NamedQuery(name = IamApprovedSite.QUERY_BY_USER_ID,
        query = "select a from IamApprovedSite a where a.userId = :" + IamApprovedSite.PARAM_USER_ID),
    @NamedQuery(name = IamApprovedSite.QUERY_BY_CLIENT_ID,
        query = "select a from IamApprovedSite a where a.clientId = :"
            + IamApprovedSite.PARAM_CLIENT_ID),
    @NamedQuery(name = IamApprovedSite.QUERY_BY_CLIENT_ID_AND_USER_ID,
        query = "select a from IamApprovedSite a where a.clientId = :"
            + IamApprovedSite.PARAM_CLIENT_ID + " and a.userId = :"
            + IamApprovedSite.PARAM_USER_ID)})
public class IamApprovedSite {

  public static final String QUERY_BY_CLIENT_ID_AND_USER_ID = "IamApprovedSite.getByClientIdAndUserId";
  public static final String QUERY_BY_CLIENT_ID = "IamApprovedSite.getByClientId";
  public static final String QUERY_BY_USER_ID = "IamApprovedSite.getByUserId";
  public static final String QUERY_ALL = "IamApprovedSite.getAll";

  public static final String PARAM_CLIENT_ID = "clientId";
  public static final String PARAM_USER_ID = "userId";

  // unique id
  private Long id;

  // which user made the approval
  private String userId;

  // which OAuth2 client is this tied to
  private String clientId;

  // when was this first approved?
  private Date creationDate;

  // when was this last accessed?
  private Date accessDate;

  // if this is a time-limited access, when does it run out?
  private Date timeoutDate;

  // what scopes have been allowed
  // this should include all information for what data to access
  private Set<String> allowedScopes;

  public IamApprovedSite() {
    // Empty constructor
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
  @Column(name = "user_id")
  public String getUserId() {
    return userId;
  }

  public void setUserId(String userId) {
    this.userId = userId;
  }

  @Basic
  @Column(name = "client_id")
  public String getClientId() {
    return clientId;
  }

  public void setClientId(String clientId) {
    this.clientId = clientId;
  }

  @Basic
  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "creation_date")
  public Date getCreationDate() {
    return creationDate;
  }

  public void setCreationDate(Date creationDate) {
    this.creationDate = creationDate;
  }

  @Basic
  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "access_date")
  public Date getAccessDate() {
    return accessDate;
  }

  public void setAccessDate(Date accessDate) {
    this.accessDate = accessDate;
  }

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "approved_site_scope", joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "scope")
  public Set<String> getAllowedScopes() {
    return allowedScopes;
  }

  public void setAllowedScopes(Set<String> allowedScopes) {
    this.allowedScopes = allowedScopes;
  }

  @Basic
  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "timeout_date")
  public Date getTimeoutDate() {
    return timeoutDate;
  }

  public void setTimeoutDate(Date timeoutDate) {
    this.timeoutDate = timeoutDate;
  }

  @Transient
  public boolean isExpired() {
    if (getTimeoutDate() != null) {
      Date now = new Date();
      return now.after(getTimeoutDate());
    }
    return false;
  }

}
