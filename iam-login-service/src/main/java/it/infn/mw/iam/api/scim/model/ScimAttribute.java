package it.infn.mw.iam.api.scim.model;

import javax.validation.constraints.NotBlank;

import org.hibernate.validator.constraints.Length;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class ScimAttribute {

  @NotBlank
  @Length(max = 64)
  private final String name;

  @Length(max = 256)
  private final String value;

  @JsonCreator
  private ScimAttribute(@JsonProperty("name") String name, @JsonProperty("value") String value) {
    this.name = name;
    this.value = value;
  }

  public String getName() {
    return name;
  }

  public String getValue() {
    return value;
  }

  private ScimAttribute(Builder builder) {
    this.name = builder.name;
    this.value = builder.value;
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {
    private String name;
    private String value;

    public Builder withName(String name) {
      this.name = name;
      return this;
    }

    public Builder withVaule(String value) {
      this.value = value;
      return this;
    }

    public ScimAttribute build() {
      return new ScimAttribute(this);
    }
  }
}
