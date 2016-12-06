package it.infn.mw.iam.api.account.password_reset;

import javax.validation.constraints.NotNull;

import org.hibernate.validator.constraints.Email;

public class EmailDTO {

  @Email(message = "please specify a valid email address")
  @NotNull(message = "please specify an email address")
  private String email;

  public EmailDTO() {}

  public String getEmail() {
    return email;
  }

  public void setEmail(String email) {
    this.email = email;
  }

}
