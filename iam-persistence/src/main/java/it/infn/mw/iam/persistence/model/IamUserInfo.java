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

import static it.infn.mw.iam.core.NameUtils.getFormatted;
import static java.util.Objects.isNull;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;
import javax.persistence.Table;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

@Entity
@Table(name = "iam_user_info")
public class IamUserInfo implements Serializable {

  /**
   * 
   */
  private static final long serialVersionUID = -6656950721943983944L;

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @OneToOne(mappedBy = "userInfo")
  private IamAccount iamAccount;

  @Column(name="givenname", nullable = false, length = 64)
  private String givenName;

  @Column(name="familyname", nullable = false, length = 64)
  private String familyName;

  @Column(name="middlename", length = 64)
  private String middleName;

  private String nickname;

  private String profile;

  private String picture;

  private String website;

  @Column(nullable = false, length = 128)
  private String email;

  @Column(name="emailverified")
  private Boolean emailVerified;

  private String gender;
  private String zoneinfo;
  private String locale;
  
  @Column(name="phonenumber")
  private String phoneNumber;

  @Column(name="phonenumberverified")
  private Boolean phoneNumberVerified;
  
  @OneToOne(optional=true, cascade=CascadeType.ALL)
  @JoinColumn(name="address_id")
  private IamAddress address;

  private String birthdate;

  private transient JsonObject src;

  public IamAddress getAddress() {

    return address;
  }

  public String getBirthdate() {

    return birthdate;
  }

  public String getEmail() {

    return email;
  }

  public Boolean getEmailVerified() {

    return emailVerified;
  }

  public String getFamilyName() {

    return familyName;
  }

  public String getGender() {

    return gender;
  }

  public String getGivenName() {

    return givenName;
  }

  public IamAccount getIamAccount() {

    return iamAccount;
  }

  public Long getId() {

    return id;
  }

  public String getLocale() {

    return locale;
  }

  public String getMiddleName() {

    return middleName;
  }

  public String getNickname() {

    return nickname;
  }

  public String getPhoneNumber() {

    return phoneNumber;
  }

  public Boolean getPhoneNumberVerified() {

    return phoneNumberVerified;
  }

  public String getPicture() {

    return picture;
  }

  public String getPreferredUsername() {

    return iamAccount.getUsername();
  }

  public String getProfile() {

    return profile;
  }


  public JsonObject getSource() {
    return src;
  }

  public JsonObject getSrc() {
    return getSource();
  }

  public String getSub() {

    return iamAccount.getUuid();
  }

  public long getUpdatedTime() {
    return getIamAccount().getLastUpdateTime().toInstant().getEpochSecond();
  }

  public String getWebsite() {

    return website;
  }

  public String getZoneinfo() {

    return zoneinfo;
  }


  public void setAddress(IamAddress address) {

    this.address = address;
  }

  public void setBirthdate(String birthdate) {

    this.birthdate = birthdate;
  }

  public void setEmail(String email) {

    this.email = email;
  }

  public void setEmailVerified(Boolean emailVerified) {

    this.emailVerified = emailVerified;
  }

  public void setFamilyName(String familyName) {

    this.familyName = familyName;
  }

  public void setGender(String gender) {

    this.gender = gender;
  }

  public void setGivenName(String givenName) {

    this.givenName = givenName;
  }

  public void setIamAccount(IamAccount iamAccount) {

    this.iamAccount = iamAccount;
  }

  public void setId(Long id) {

    this.id = id;
  }

  public void setLocale(String locale) {

    this.locale = locale;
  }

  public void setMiddleName(String middleName) {

    this.middleName = middleName;
  }

  public void setNickname(String nickname) {

    this.nickname = nickname;
  }

  public void setPhoneNumber(String phoneNumber) {

    this.phoneNumber = phoneNumber;
  }

  public void setPhoneNumberVerified(Boolean phoneNumberVerified) {

    this.phoneNumberVerified = phoneNumberVerified;
  }

  public void setPicture(String picture) {

    this.picture = picture;
  }

  public void setPreferredUsername(String preferredUsername) {

    // NO-OP
  }

  public void setProfile(String profile) {

    this.profile = profile;
  }

  public void setSrc(JsonObject src) {

    this.src = src;
  }


  public void setSub(String sub) {

    // NO-OP

  }

  public void setUpdatedTime(String updatedTime) {

    // NO-OP
  }

  public void setWebsite(String website) {

    this.website = website;
  }

  public void setZoneinfo(String zoneinfo) {

    this.zoneinfo = zoneinfo;
  }

  public Set<IamGroup> getGroups() {

    Set<IamGroup> groups = new HashSet<>();
    for (IamAccountGroupMembership m : iamAccount.getGroups()) {
      groups.add(m.getGroup());
    }
    return groups;
  }

  public JsonObject toJson() {

    if (src == null) {

      JsonObject obj = new JsonObject();

      obj.addProperty("sub", this.getSub());

      obj.addProperty("name", this.getName());
      obj.addProperty("preferred_username", this.getPreferredUsername());
      obj.addProperty("given_name", this.getGivenName());
      obj.addProperty("family_name", this.getFamilyName());
      obj.addProperty("middle_name", this.getMiddleName());
      obj.addProperty("nickname", this.getNickname());
      obj.addProperty("profile", this.getProfile());
      obj.addProperty("picture", this.getPicture());
      obj.addProperty("website", this.getWebsite());
      obj.addProperty("gender", this.getGender());
      obj.addProperty("zoneinfo", this.getZoneinfo());
      obj.addProperty("locale", this.getLocale());
      obj.addProperty("updated_at", this.getUpdatedTime());
      obj.addProperty("birthdate", this.getBirthdate());

      obj.addProperty("email", this.getEmail());
      obj.addProperty("email_verified", this.getEmailVerified());

      obj.addProperty("phone_number", this.getPhoneNumber());
      obj.addProperty("phone_number_verified", this.getPhoneNumberVerified());

      if (this.getAddress() != null) {

        JsonObject addr = new JsonObject();
        addr.addProperty("formatted", this.getAddress().getFormatted());
        addr.addProperty("street_address", this.getAddress().getStreetAddress());
        addr.addProperty("locality", this.getAddress().getLocality());
        addr.addProperty("region", this.getAddress().getRegion());
        addr.addProperty("postal_code", this.getAddress().getPostalCode());
        addr.addProperty("country", this.getAddress().getCountry());

        obj.add("address", addr);
      }

      if (getGroups() != null) {

        JsonArray groups = new JsonArray();

        for (IamGroup g : getGroups()) {
          groups.add(new JsonPrimitive(g.getName()));
        }

        obj.add("groups", groups);
      }

      if (!isNull(getIamAccount().getSshKeys())) {
        JsonArray sshKeys = new JsonArray();

        for (IamSshKey k : getIamAccount().getSshKeys()) {
          JsonObject sshKey = new JsonObject();
          sshKey.addProperty("fingerprint", k.getFingerprint());
          sshKey.addProperty("value", k.getValue());
          sshKeys.add(sshKey);
        }

        obj.add("ssh_keys", sshKeys);
      }

      return obj;
    } else {
      return src;
    }

  }
  
  
  public String getName() {

    return getFormatted(this.givenName, this.middleName, this.familyName);
  }
  
  public void setName(String name) {

    // NO-OP

  }

  @Override
  public String toString() {

    return "IamUserInfo [givenName=" + givenName + ", familyName=" + familyName + ", email=" + email
        + "]";
  }

}
