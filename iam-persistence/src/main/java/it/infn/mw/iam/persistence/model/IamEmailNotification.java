package it.infn.mw.iam.persistence.model;

import java.util.Date;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

import it.infn.mw.iam.core.IamDeliveryStatus;
import it.infn.mw.iam.core.IamNotificationType;

@Entity
@Table(name = "iam_email_notification")
public class IamEmailNotification {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false, length = 36, unique = true)
  private String uuid;

  @Enumerated(EnumType.STRING)
  @Column(name = "notification_type", nullable = false)
  private IamNotificationType notificationType;

  @Column(length = 128)
  private String subject;

  @Column
  private String body;

  @OneToMany(mappedBy = "iamEmailNotification", cascade = CascadeType.ALL)
  private List<IamNotificationReceiver> receivers;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "creation_time", nullable = false)
  private Date creationTime;

  @Enumerated(EnumType.STRING)
  @Column(name = "delivery_status")
  private IamDeliveryStatus deliveryStatus;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "last_update", nullable = true)
  private Date lastUpdate;

  @JoinColumn(name = "request_id")
  private IamRegistrationRequest request;

  public IamEmailNotification() {}

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public String getUuid() {
    return uuid;
  }

  public void setUuid(String uuid) {
    this.uuid = uuid;
  }



  public IamNotificationType getType() {
    return notificationType;
  }

  public void setType(IamNotificationType type) {
    this.notificationType = type;
  }

  public String getSubject() {
    return subject;
  }

  public void setSubject(String subject) {
    this.subject = subject;
  }

  public String getBody() {
    return body;
  }

  public void setBody(String body) {
    this.body = body;
  }

  public List<IamNotificationReceiver> getReceivers() {
    return receivers;
  }

  public void setReceivers(List<IamNotificationReceiver> receivers) {
    this.receivers = receivers;
  }

  public Date getCreationTime() {
    return creationTime;
  }

  public void setCreationTime(Date creationTime) {
    this.creationTime = creationTime;
  }

  public IamDeliveryStatus getDeliveryStatus() {
    return deliveryStatus;
  }

  public void setDeliveryStatus(IamDeliveryStatus deliveryStatus) {
    this.deliveryStatus = deliveryStatus;
  }

  public Date getLastUpdate() {
    return lastUpdate;
  }

  public void setLastUpdate(Date lastUpdate) {
    this.lastUpdate = lastUpdate;
  }

  public IamRegistrationRequest getRequest() {
    return request;
  }

  public void setRequest(IamRegistrationRequest request) {
    this.request = request;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((id == null) ? 0 : id.hashCode());
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
    IamEmailNotification other = (IamEmailNotification) obj;
    if (id == null) {
      if (other.id != null)
        return false;
    } else if (!id.equals(other.id)) {
      return false;
    }
    return true;
  }

  @Override
  public String toString() {
    return "IamEmailNotification [id=" + id + ", uuid=" + uuid + ", type=" + notificationType
        + ", subject=" + subject + ", creationTime=" + creationTime + ", deliveryStatus="
        + deliveryStatus + ", lastUpdate=" + lastUpdate + "]";
  }

}
