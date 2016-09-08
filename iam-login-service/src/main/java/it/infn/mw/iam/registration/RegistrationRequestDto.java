package it.infn.mw.iam.registration;

import java.util.Date;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class RegistrationRequestDto {

  private String uuid;
  private Date creationTime;
  private String status;
  private Date lastUpdateTime;
  private String username;
  private String password;
  private String givenname;
  private String familyname;
  private String email;
  private String birthdate;
  private String accountId;
  private String notificationStatus;
  private String notes;

  public RegistrationRequestDto() {}

  @JsonCreator
  public RegistrationRequestDto(@JsonProperty("uuid") String uuid,
      @JsonProperty("creationdate") Date creationTime, @JsonProperty("status") String status,
      @JsonProperty("lastupdatetime") Date lastUpdateTime,
      @JsonProperty("username") String username, @JsonProperty("password") String password,
      @JsonProperty("givename") String givenname, @JsonProperty("familyname") String familyname,
      @JsonProperty("email") String email, @JsonProperty("birthdate") String birthdate,
      @JsonProperty("accountid") String accountId,
      @JsonProperty("notificationstatus") String notificationStatus,
      @JsonProperty("notes") String notes) {
    super();
    this.username = username;
    this.password = password;
    this.givenname = givenname;
    this.familyname = familyname;
    this.email = email;
    this.birthdate = birthdate;
    this.uuid = uuid;
    this.creationTime = creationTime;
    this.status = status;
    this.lastUpdateTime = lastUpdateTime;
    this.accountId = accountId;
    this.notificationStatus = notificationStatus;
    this.notes = notes;
  }

  public String getUuid() {

    return uuid;
  }

  public void setUuid(String uuid) {

    this.uuid = uuid;
  }

  public Date getCreationTime() {

    return creationTime;
  }

  public void setCreationTime(Date creationTime) {

    this.creationTime = creationTime;
  }

  public String getStatus() {

    return status;
  }

  public void setStatus(String status) {

    this.status = status;
  }

  public Date getLastUpdateTime() {

    return lastUpdateTime;
  }

  public void setLastUpdateTime(Date lastUpdateTime) {

    this.lastUpdateTime = lastUpdateTime;
  }

  public String getUsername() {

    return username;
  }

  public void setUsername(String username) {

    this.username = username;
  }

  public String getPassword() {

    return password;
  }

  public void setPassword(String password) {

    this.password = password;
  }

  public String getGivenname() {

    return givenname;
  }

  public void setGivenname(String givenname) {

    this.givenname = givenname;
  }

  public String getFamilyname() {

    return familyname;
  }

  public void setFamilyname(String familyname) {

    this.familyname = familyname;
  }

  public String getEmail() {

    return email;
  }

  public void setEmail(String email) {

    this.email = email;
  }

  public String getBirthdate() {

    return birthdate;
  }

  public void setBirthdate(String birthdate) {

    this.birthdate = birthdate;
  }

  public String getAccountId() {

    return accountId;
  }

  public void setAccountId(String accountId) {

    this.accountId = accountId;
  }

  public String getNotificationStatus() {
    return notificationStatus;
  }

  public void setNotificationStatus(String notificationStatus) {
    this.notificationStatus = notificationStatus;
  }

  public String getNotes() {
    return notes;
  }

  public void setNotes(String notes) {
    this.notes = notes;
  }

}
