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
package it.infn.mw.iam.core.userinfo;

import org.mitre.openid.connect.model.Address;
import org.mitre.openid.connect.model.UserInfo;

import com.google.gson.JsonObject;

public class DelegateUserInfoAdapter implements UserInfo {

  private static final long serialVersionUID = 1L;
  
  private final UserInfo delegate;
  
  public DelegateUserInfoAdapter(UserInfo delegate) {
    this.delegate = delegate;
  }

  public String getSub() {
    return delegate.getSub();
  }

  public void setSub(String sub) {
    delegate.setSub(sub);
  }

  public String getPreferredUsername() {
    return delegate.getPreferredUsername();
  }

  public void setPreferredUsername(String preferredUsername) {
    delegate.setPreferredUsername(preferredUsername);
  }

  public String getName() {
    return delegate.getName();
  }

  public void setName(String name) {
    delegate.setName(name);
  }

  public String getGivenName() {
    return delegate.getGivenName();
  }

  public void setGivenName(String givenName) {
    delegate.setGivenName(givenName);
  }

  public String getFamilyName() {
    return delegate.getFamilyName();
  }

  public void setFamilyName(String familyName) {
    delegate.setFamilyName(familyName);
  }

  public String getMiddleName() {
    return delegate.getMiddleName();
  }

  public void setMiddleName(String middleName) {
    delegate.setMiddleName(middleName);
  }

  public String getNickname() {
    return delegate.getNickname();
  }

  public void setNickname(String nickname) {
    delegate.setNickname(nickname);
  }

  public String getProfile() {
    return delegate.getProfile();
  }

  public void setProfile(String profile) {
    delegate.setProfile(profile);
  }

  public String getPicture() {
    return delegate.getPicture();
  }

  public void setPicture(String picture) {
    delegate.setPicture(picture);
  }

  public String getWebsite() {
    return delegate.getWebsite();
  }

  public void setWebsite(String website) {
    delegate.setWebsite(website);
  }

  public String getEmail() {
    return delegate.getEmail();
  }

  public void setEmail(String email) {
    delegate.setEmail(email);
  }

  public Boolean getEmailVerified() {
    return delegate.getEmailVerified();
  }

  public void setEmailVerified(Boolean emailVerified) {
    delegate.setEmailVerified(emailVerified);
  }

  public String getGender() {
    return delegate.getGender();
  }

  public void setGender(String gender) {
    delegate.setGender(gender);
  }

  public String getZoneinfo() {
    return delegate.getZoneinfo();
  }

  public void setZoneinfo(String zoneinfo) {
    delegate.setZoneinfo(zoneinfo);
  }

  public String getLocale() {
    return delegate.getLocale();
  }

  public void setLocale(String locale) {
    delegate.setLocale(locale);
  }

  public String getPhoneNumber() {
    return delegate.getPhoneNumber();
  }

  public void setPhoneNumber(String phoneNumber) {
    delegate.setPhoneNumber(phoneNumber);
  }

  public Boolean getPhoneNumberVerified() {
    return delegate.getPhoneNumberVerified();
  }

  public void setPhoneNumberVerified(Boolean phoneNumberVerified) {
    delegate.setPhoneNumberVerified(phoneNumberVerified);
  }

  public Address getAddress() {
    return delegate.getAddress();
  }

  public void setAddress(Address address) {
    delegate.setAddress(address);
  }

  public String getUpdatedTime() {
    return delegate.getUpdatedTime();
  }

  public void setUpdatedTime(String updatedTime) {
    delegate.setUpdatedTime(updatedTime);
  }

  public String getBirthdate() {
    return delegate.getBirthdate();
  }

  public void setBirthdate(String birthdate) {
    delegate.setBirthdate(birthdate);
  }

  public JsonObject toJson() {
    return delegate.toJson();
  }

  public JsonObject getSource() {
    return delegate.getSource();
  }

  protected UserInfo getDelegate() {
    return getDelegate();
  }
}
