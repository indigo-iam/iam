package it.infn.mw.iam.api.scim.model;

import javax.validation.constraints.NotNull;

import org.hibernate.validator.constraints.NotEmpty;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class ScimPhoto {

  @NotEmpty
  @NotNull
  private final String value;

  @NotEmpty
  @NotNull
  private final ScimPhotoType type;

  public static enum ScimPhotoType {
    thumbnail, photo;
  }

  @JsonCreator
  private ScimPhoto(@JsonProperty("value") String value, @JsonProperty("type") ScimPhotoType type) {

    this.value = value;
    this.type = type;
  }

  public String getValue() {

    return this.value;
  }

  public ScimPhotoType getType() {

    return this.type;
  }

  private ScimPhoto(Builder b) {

    this.value = b.value;
    this.type = b.type;
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
    ScimPhoto other = (ScimPhoto) obj;
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
    private ScimPhotoType type;

    public Builder() {

      this.type = ScimPhotoType.photo;
    }

    public Builder value(String value) {

      this.value = value;
      return this;
    }

    public ScimPhoto build() {

      return new ScimPhoto(this);
    }
  }
}
