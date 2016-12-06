package it.infn.mw.iam.api.scim.model;

import org.hibernate.validator.constraints.NotEmpty;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public final class ScimMemberRef {

  @NotEmpty
  private final String value;

  private final String display;
  private final String ref;

  @JsonCreator
  private ScimMemberRef(@JsonProperty("display") String display,
      @JsonProperty("value") String value, @JsonProperty("$ref") String ref) {

    this.display = display;
    this.value = value;
    this.ref = ref;
  }

  private ScimMemberRef(Builder builder) {

    value = builder.value;
    display = builder.display;
    ref = builder.ref;
  }

  @JsonProperty("$ref")
  public String getRef() {

    return ref;
  }

  public String getValue() {

    return value;
  }

  public String getDisplay() {

    return display;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
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
    ScimMemberRef other = (ScimMemberRef) obj;
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

    private String value;
    private String display;
    private String ref;

    public Builder value(String value) {

      this.value = value;
      return this;
    }

    public Builder display(String display) {

      this.display = display;
      return this;
    }

    public Builder ref(String ref) {

      this.ref = ref;
      return this;
    }

    public ScimMemberRef build() {

      return new ScimMemberRef(this);
    }
  }
}
