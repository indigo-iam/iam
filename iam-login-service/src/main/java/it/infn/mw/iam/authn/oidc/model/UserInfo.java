package it.infn.mw.iam.authn.oidc.model;

import java.io.Serializable;

import com.google.gson.JsonObject;

public interface UserInfo extends Serializable {

  public String getSub();

  public void setSub(String sub);

  public String getPreferredUsername();

  public void setPreferredUsername(String preferredUsername);

  public String getName();

  public void setName(String name);

  public String getGivenName();

  public void setGivenName(String givenName);

  public String getFamilyName();

  public void setFamilyName(String familyName);

  public String getMiddleName();

  public void setMiddleName(String middleName);

  public String getNickname();

  public void setNickname(String nickname);

  public String getProfile();

  public void setProfile(String profile);

  public String getPicture();

  public void setPicture(String picture);

  public String getWebsite();

  public void setWebsite(String website);

  public String getEmail();

  public void setEmail(String email);

  public Boolean getEmailVerified();

  public void setEmailVerified(Boolean emailVerified);

  public String getGender();

  public void setGender(String gender);

  public String getZoneinfo();

  public void setZoneinfo(String zoneinfo);

  public String getLocale();

  public void setLocale(String locale);

  public String getPhoneNumber();

  public void setPhoneNumber(String phoneNumber);

  public Boolean getPhoneNumberVerified();

  public void setPhoneNumberVerified(Boolean phoneNumberVerified);

  public Address getAddress();

  public void setAddress(Address address);

  public String getUpdatedTime();

  public void setUpdatedTime(String updatedTime);

  public String getBirthdate();

  public void setBirthdate(String birthdate);

  public JsonObject toJson();

  public JsonObject getSource();

}
