package it.infn.mw.iam.api.account.authority;

import javax.validation.constraints.Size;

import org.hibernate.validator.constraints.NotBlank;

public class AuthorityDTO {

  @NotBlank(message = "Authority cannot be an empty string")
  @Size(max = 128, message = "Invalid authority size")
  private String authority;

  public AuthorityDTO() {

  }

  public String getAuthority() {
    return authority;
  }

  public void setAuthority(String authority) {
    this.authority = authority;
  }

}
