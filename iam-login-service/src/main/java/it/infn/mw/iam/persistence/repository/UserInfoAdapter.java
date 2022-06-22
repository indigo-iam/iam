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
package it.infn.mw.iam.persistence.repository;

import static java.lang.String.format;

import org.mitre.openid.connect.model.Address;
import org.mitre.openid.connect.model.UserInfo;

import com.google.gson.JsonObject;

import it.infn.mw.iam.persistence.model.IamUserInfo;

public class UserInfoAdapter implements UserInfo {


  private static final long serialVersionUID = 1L;

  final IamUserInfo userinfo;

  private UserInfoAdapter(IamUserInfo userinfo) {
    this.userinfo = userinfo;
  }

  public String getBirthdate() {
    return userinfo.getBirthdate();
  }

  public String getEmail() {
    return userinfo.getEmail();
  }

  public Boolean getEmailVerified() {
    return userinfo.getEmailVerified();
  }

  public String getFamilyName() {
    return userinfo.getFamilyName();
  }

  public String getGender() {
    return userinfo.getGender();
  }

  public String getGivenName() {
    return userinfo.getGivenName();
  }

  public String getLocale() {
    return userinfo.getLocale();
  }

  public String getMiddleName() {
    return userinfo.getMiddleName();
  }

  public String getNickname() {
    return userinfo.getNickname();
  }

  public String getPhoneNumber() {
    return userinfo.getPhoneNumber();
  }

  public Boolean getPhoneNumberVerified() {
    return userinfo.getPhoneNumberVerified();
  }

  public String getPicture() {
    return userinfo.getPicture();
  }

  public String getPreferredUsername() {
    return userinfo.getPreferredUsername();
  }

  public String getProfile() {
    return userinfo.getProfile();
  }

  public JsonObject getSource() {
    return userinfo.getSource();
  }

  public String getSub() {
    return userinfo.getSub();
  }

  public String getWebsite() {
    return userinfo.getWebsite();
  }

  public String getZoneinfo() {
    return userinfo.getZoneinfo();
  }

 

  public void setBirthdate(String birthdate) {
    userinfo.setBirthdate(birthdate);
  }

  public void setEmail(String email) {
    userinfo.setEmail(email);
  }

  public void setEmailVerified(Boolean emailVerified) {
    userinfo.setEmailVerified(emailVerified);
  }

  public void setFamilyName(String familyName) {
    userinfo.setFamilyName(familyName);
  }

  public void setGender(String gender) {
    userinfo.setGender(gender);
  }

  public void setGivenName(String givenName) {
    userinfo.setGivenName(givenName);
  }

  public void setLocale(String locale) {
    userinfo.setLocale(locale);
  }

  public void setMiddleName(String middleName) {
    userinfo.setMiddleName(middleName);
  }

  public void setNickname(String nickname) {
    userinfo.setNickname(nickname);
  }

  public void setPhoneNumber(String phoneNumber) {
    userinfo.setPhoneNumber(phoneNumber);
  }

  public void setPhoneNumberVerified(Boolean phoneNumberVerified) {
    userinfo.setPhoneNumberVerified(phoneNumberVerified);
  }

  public void setPicture(String picture) {
    userinfo.setPicture(picture);
  }

  public void setPreferredUsername(String preferredUsername) {
    userinfo.setPreferredUsername(preferredUsername);
  }

  public void setProfile(String profile) {
    userinfo.setProfile(profile);
  }

  public void setSrc(JsonObject src) {
    userinfo.setSrc(src);
  }

  public void setSub(String sub) {
    userinfo.setSub(sub);
  }

  public void setUpdatedTime(String updatedTime) {
    userinfo.setUpdatedTime(updatedTime);
  }

  public void setWebsite(String website) {
    userinfo.setWebsite(website);
  }

  public void setZoneinfo(String zoneinfo) {
    userinfo.setZoneinfo(zoneinfo);
  }

  public JsonObject toJson() {
    return userinfo.toJson();
  }

  public String getName() {
    return userinfo.getName();
  }

  public void setName(String name) {
    userinfo.setName(name);
  }

  @Override
  public Address getAddress() {

    return AddressAdapter.forIamAddress(userinfo.getAddress());

  }

  @Override
  public void setAddress(Address address) {
    // no op
  }



  @Override
  public String getUpdatedTime() {
    return format("%d", userinfo.getUpdatedTime());
  }


  public static UserInfoAdapter forIamUserInfo(IamUserInfo info) {
    return new UserInfoAdapter(info);
  }

  public IamUserInfo getUserinfo() {
    return userinfo;
  }  

}
