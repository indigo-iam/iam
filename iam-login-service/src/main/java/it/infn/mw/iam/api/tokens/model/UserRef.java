package it.infn.mw.iam.api.tokens.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class UserRef {

  private String id;
  private String userName;
  private String ref;

  @JsonCreator
  public UserRef(@JsonProperty("id") String id, @JsonProperty("userName") String userName,
      @JsonProperty("$ref") String ref) {

    this.id = id;
    this.userName = userName;
    this.ref = ref;
  }

  public UserRef(Builder builder) {

    this.id = builder.id;
    this.userName = builder.userName;
    this.ref = builder.ref;
  }

  @JsonProperty("id")
  public String getId() {
    return id;
  }

  @JsonProperty("userName")
  public String getUserName() {
    return userName;
  }

  @JsonProperty("$ref")
  public String getRef() {
    return ref;
  }

  @Override
  public String toString() {
    return "User [id=" + id + ", userName=" + userName + ", ref=" + ref + "]";
  }

  public static Builder builder() {

    return new Builder();
  }

  public static class Builder {

    private String id;
    private String userName;
    private String ref;

    public Builder id(String id) {
      this.id = id;
      return this;
    }

    public Builder userName(String userName) {
      this.userName = userName;
      return this;
    }

    public Builder ref(String ref) {
      this.ref = ref;
      return this;
    }

    public UserRef build() {
      return new UserRef(this);
    }
  }
}
