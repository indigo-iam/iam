package it.infn.mw.iam.api.scim.model;

import java.util.Objects;

import javax.validation.constraints.NotEmpty;

import org.hibernate.validator.constraints.Length;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class ScimAuthority {

  @NotEmpty
  @Length(max = 128)
  private String authority;

  @JsonCreator
  private ScimAuthority(@JsonProperty("authority") String authority) {
    this.authority = authority;
  }

  public String getAuthority() {
    return authority;
  }

  public void setAuthority(String authority) {
    this.authority = authority;
  }

  @Override
  public int hashCode() {
    return Objects.hash(authority);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    ScimAuthority other = (ScimAuthority) obj;
    return Objects.equals(authority, other.authority);
  }

  private ScimAuthority(Builder builder) {
    this.authority = builder.authority;
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {
    private String authority;

    public Builder withAuthority(String authority) {
      this.authority = authority;
      return this;
    }

    public ScimAuthority build() {
      return new ScimAuthority(this);
    }
  }
}
