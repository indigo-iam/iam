package it.infn.mw.iam.api.tokens.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class IdTokenRef {

  private Long id;
  private String ref;

  @JsonCreator
  public IdTokenRef(@JsonProperty("id") Long id, @JsonProperty("$ref") String ref) {

    this.id = id;
    this.ref = ref;
  }

  public IdTokenRef(Builder builder) {

    this.id = builder.id;
    this.ref = builder.ref;
  }

  @JsonProperty("id")
  public Long getId() {

    return id;
  }

  @JsonProperty("$ref")
  public String getRef() {

    return ref;
  }

  @Override
  public String toString() {
    return "IdToken [id=" + id + ", ref=" + ref + "]";
  }

  public static Builder builder() {

    return new Builder();
  }

  public static class Builder {

    private Long id;
    private String ref;

    public Builder id(Long id) {
      this.id = id;
      return this;
    }

    public Builder ref(String ref) {
      this.ref = ref;
      return this;
    }

    public IdTokenRef build() {
      return new IdTokenRef(this);
    }
  }
}

