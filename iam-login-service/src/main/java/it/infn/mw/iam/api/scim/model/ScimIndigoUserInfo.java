package it.infn.mw.iam.api.scim.model;

import org.mitre.openid.connect.model.Address;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class ScimIndigoUserInfo {

  private final String givenName;
  private final String familyName;
  private final String middleName;
  private final String nickname;
  private final String profile;
  private final String picture;
  private final String website;
  private final String email;
  private final Boolean emailVerified;
  private final String gender;
  private final String zoneinfo;
  private final String locale;
  private final String phoneNumber;
  private final Boolean phoneNumberVerified;
  private final Address address;
  private final String birthdate;

  @JsonCreator
  private ScimIndigoUserInfo(@JsonProperty("givenName") String givenName,
      @JsonProperty("familyName") String familyName, @JsonProperty("middleName") String middleName,
      @JsonProperty("nickname") String nickname, @JsonProperty("profile") String profile,
      @JsonProperty("picture") String picture, @JsonProperty("website") String website,
      @JsonProperty("email") String email, @JsonProperty("emailVerified") Boolean emailVerified,
      @JsonProperty("gender") String gender, @JsonProperty("zoneinfo") String zoneinfo,
      @JsonProperty("locale") String locale, @JsonProperty("phoneNumber") String phoneNumber,
      @JsonProperty("phoneNumberVerified") Boolean phoneNumberVerified,
      @JsonProperty("address") Address address, @JsonProperty("birthdate") String birthdate) {

    this.givenName = givenName;
    this.familyName = familyName;
    this.middleName = middleName;
    this.nickname = nickname;
    this.profile = profile;
    this.picture = picture;
    this.website = website;
    this.email = email;
    this.emailVerified = emailVerified;
    this.gender = gender;
    this.zoneinfo = zoneinfo;
    this.locale = locale;
    this.phoneNumber = phoneNumber;
    this.phoneNumberVerified = phoneNumberVerified;
    this.address = address;
    this.birthdate = birthdate;
    
  }
  
  public String getGivenName() {
    return givenName;
  }

  public String getFamilyName() {
    return familyName;
  }

  public String getMiddleName() {
    return middleName;
  }

  public String getNickname() {
    return nickname;
  }

  public String getProfile() {
    return profile;
  }

  public String getPicture() {
    return picture;
  }

  public String getWebsite() {
    return website;
  }

  public String getEmail() {
    return email;
  }

  public Boolean getEmailVerified() {
    return emailVerified;
  }

  public String getGender() {
    return gender;
  }

  public String getZoneinfo() {
    return zoneinfo;
  }

  public String getLocale() {
    return locale;
  }

  public String getPhoneNumber() {
    return phoneNumber;
  }

  public Boolean getPhoneNumberVerified() {
    return phoneNumberVerified;
  }

  public Address getAddress() {
    return address;
  }

  public String getBirthdate() {
    return birthdate;
  }

  public ScimIndigoUserInfo(Builder b) {
    
    this.givenName = b.givenName;
    this.familyName = b.familyName;
    this.middleName = b.middleName;
    this.nickname = b.nickname;
    this.profile = b.profile;
    this.picture = b.picture;
    this.website = b.website;
    this.email = b.email;
    this.emailVerified = b.emailVerified;
    this.gender = b.gender;
    this.zoneinfo = b.zoneinfo;
    this.locale = b.locale;
    this.phoneNumber = b.phoneNumber;
    this.phoneNumberVerified = b.phoneNumberVerified;
    this.address = b.address;
    this.birthdate = b.birthdate;
  }

  public static Builder builder() {

    return new Builder();
  }

  public static class Builder {
    
    private String givenName;
    private String familyName;
    private String middleName;
    private String nickname;
    private String profile;
    private String picture;
    private String website;
    private String email;
    private Boolean emailVerified;
    private String gender;
    private String zoneinfo;
    private String locale;
    private String phoneNumber;
    private Boolean phoneNumberVerified;
    private Address address;
    private String birthdate;
    
    public Builder() {
    }
    
    public Builder givenName(String givenName) {
      
      this.givenName = givenName;
      return this;
    }
    
    public Builder familyName(String familyName) {
      
      this.familyName = familyName;
      return this;
    }
    
    public Builder middleName(String middleName) {
      
      this.middleName = middleName;
      return this;
    }
   
    
    public Builder nickname(String nickname) {
      
      this.nickname = nickname;
      return this;
    }
    
    public Builder profile(String profile) {
      
      this.profile = profile;
      return this;
    }
    
    public Builder picture(String picture) {
      
      this.picture = picture;
      return this;
    }
    
    public Builder website(String website) {
      
      this.website = website;
      return this;
    }
    
    public Builder email(String email) {
      
      this.email = email;
      return this;
    }
    
    public Builder emailVerified(Boolean emailVerified) {
      
      this.emailVerified = emailVerified;
      return this;
    }
    
    public Builder gender(String gender) {
      
      this.gender = gender;
      return this;
    }
    
    public Builder zoneinfo(String zoneinfo) {
      
      this.zoneinfo = zoneinfo;
      return this;
    }
    
    public Builder locale(String locale) {
      
      this.locale = locale;
      return this;
    }
    
    public Builder phoneNumber(String phoneNumber) {
      
      this.phoneNumber = phoneNumber;
      return this;
    }
    
    public Builder phoneNumberVerified(Boolean phoneNumberVerified) {
      
      this.phoneNumberVerified = phoneNumberVerified;
      return this;
    }
    
    public Builder address(Address address) {
      
      this.address = address;
      return this;
    }
    
    public Builder birthdate(String birthdate) {
      
      this.birthdate = birthdate;
      return this;
    }
    
    public ScimIndigoUserInfo build() {
      
      return new ScimIndigoUserInfo(this);
    }
  }
  
}
