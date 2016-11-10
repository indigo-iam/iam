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

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((primary == null) ? 0 : primary.hashCode());
    result = prime * result + ((type == null) ? 0 : type.hashCode());
    result = prime * result + ((value == null) ? 0 : value.hashCode());
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    ScimEmail other = (ScimEmail) obj;
    if (primary == null) {
      if (other.primary != null)
        return false;
    } else if (!primary.equals(other.primary))
      return false;
    if (type != other.type)
      return false;
    if (value == null) {
      if (other.value != null)
        return false;
    } else if (!value.equals(other.value))
      return false;
    return true;
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
