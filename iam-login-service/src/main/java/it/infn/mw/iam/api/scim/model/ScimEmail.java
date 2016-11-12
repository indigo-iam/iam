package it.infn.mw.iam.api.scim.model;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import org.hibernate.validator.constraints.Email;
import org.hibernate.validator.constraints.NotEmpty;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import it.infn.mw.iam.api.scim.model.ScimUser.NewUserValidation;
import it.infn.mw.iam.api.scim.model.ScimUser.UpdateUserValidation;

public class ScimEmail {

  public static enum ScimEmailType {
    work, home, other;
  }

  @NotNull
  @Valid
  private final ScimEmailType type;

  @NotEmpty(groups = {NewUserValidation.class, UpdateUserValidation.class})
  @Email(groups = {NewUserValidation.class, UpdateUserValidation.class})
  private final String value;

  @NotNull(groups = {NewUserValidation.class, UpdateUserValidation.class})
  private final Boolean primary;

  @JsonCreator
  private ScimEmail(@JsonProperty("type") ScimEmailType type, @JsonProperty("value") String value,
      @JsonProperty("primary") Boolean primary) {
    this.type = type;
    this.value = value;
    this.primary = primary;
  }

  private ScimEmail(Builder b) {
    this.type = b.type;
    this.value = b.value;
    this.primary = b.primary;
  }

  public ScimEmailType getType() {

    return type;
  }

  public String getValue() {

    return value;
  }

  public Boolean getPrimary() {

    return primary;
  }

  public static Builder builder() {

    return new Builder();
  }

  public static class Builder {

    private ScimEmailType type;
    private String value;
    private Boolean primary;

    public Builder() {
    }

    public Builder email(String value) {

      this.value = value;
      return this;
    }

    public Builder type(ScimEmailType type) {

      this.type = type;
      return this;
    }

    public Builder primary(Boolean isPrimary) {

      this.primary = isPrimary;
      return this;
    }

    public ScimEmail build() {

      return new ScimEmail(this);
    }

  }

}
