package it.infn.mw.iam.api.scim.model;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class ScimPatchOperation<T> {

  public static enum ScimPatchOperationType {
    add, remove, replace
  }

  @NotNull
  private final ScimPatchOperationType op;

  private final String path;

  @Valid
  private final T value;

  @JsonCreator
  private ScimPatchOperation(@JsonProperty("op") ScimPatchOperationType op,
      @JsonProperty("path") String path, @JsonProperty("value") T value) {

    this.op = op;
    this.path = path;
    this.value = value;
  }

  public ScimPatchOperation(Builder<T> builder) {

    this.op = builder.op;
    this.path = builder.path;
    this.value = builder.value;
  }

  public ScimPatchOperationType getOp() {

    return op;
  }

  public T getValue() {

    return value;
  }

  public String getPath() {

    return path;
  }

  public static class Builder<T> {

    ScimPatchOperationType op;
    String path;
    T value;

    public Builder() {}

    public Builder<T> path(String path) {

      this.path = path;
      return this;
    }

    public Builder<T> value(T val) {

      this.value = val;
      return this;
    }

    public Builder<T> add() {

      this.op = ScimPatchOperationType.add;
      return this;
    }

    public Builder<T> remove() {

      this.op = ScimPatchOperationType.remove;
      return this;
    }

    public Builder<T> replace() {

      this.op = ScimPatchOperationType.replace;
      return this;
    }

    public ScimPatchOperation<T> build() {

      return new ScimPatchOperation<T>(this);
    }
  }

}
