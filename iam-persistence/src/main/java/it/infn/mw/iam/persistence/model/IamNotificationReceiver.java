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

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

@Entity
@Table(name = "iam_notification_receiver")
public class IamNotificationReceiver implements Serializable {

  /**
   * 
   */
  private static final long serialVersionUID = 1L;

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @ManyToOne
  @JoinColumn(name = "notification_id")
  private IamEmailNotification iamEmailNotification;

  @Column(name = "email_address", length = 254)
  private String emailAddress;

  public IamNotificationReceiver() {
    // empty on purpose
  }

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public IamEmailNotification getIamEmailNotification() {
    return iamEmailNotification;
  }

  public void setIamEmailNotification(IamEmailNotification iamEmailNotification) {
    this.iamEmailNotification = iamEmailNotification;
  }

  public String getEmailAddress() {
    return emailAddress;
  }

  public void setEmailAddress(String emailAddress) {
    this.emailAddress = emailAddress;
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
    IamNotificationReceiver other = (IamNotificationReceiver) obj;
    if (id == null) {
      if (other.id != null)
        return false;
    } else if (!id.equals(other.id)) {
      return false;
    }
    return true;
  }

  public static IamNotificationReceiver forAddress(IamEmailNotification n, String emailAddress) {
    IamNotificationReceiver r = new IamNotificationReceiver();
    r.setEmailAddress(emailAddress);
    r.setIamEmailNotification(n);
    return r;
  }

  @Override
  public String toString() {
    return "IamNotificationReceiver [id=" + id + ", iamEmailNotification=" + iamEmailNotification
        + ", emailAddress=" + emailAddress + "]";
  }

}
