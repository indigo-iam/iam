package it.infn.mw.iam.core;

public class UserCount {

  private String numberOfUsers;

  public UserCount(String numberOfUsers) {
    this.numberOfUsers = numberOfUsers;
  }

  public String getNumberOfUsers() {
    return numberOfUsers;
  }

  public void setNumberOfUsers(String numberOfUsers) {
    this.numberOfUsers = numberOfUsers;
  }
}
