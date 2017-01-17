package it.infn.mw.iam.api.scim.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class ScimIndigoGroup {

  private ScimGroupRef parentGroup;

  @JsonCreator
  private ScimIndigoGroup(@JsonProperty("parentGroup") ScimGroupRef parentGroup) {
    this.parentGroup = parentGroup;
  }

  private ScimIndigoGroup(Builder builder) {
    this.parentGroup = builder.parentGroup;
  }

  public ScimGroupRef getParentGroup() {
    return parentGroup;
  }


  public static class Builder {
    private ScimGroupRef parentGroup = null;

    public Builder parentGroup(ScimGroupRef parentGroup) {
      this.parentGroup = parentGroup;
      return this;
    }

    public ScimIndigoGroup build() {

      return new ScimIndigoGroup(this);
    }
  }

}
