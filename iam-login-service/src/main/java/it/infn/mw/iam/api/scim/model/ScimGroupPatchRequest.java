package it.infn.mw.iam.api.scim.model;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.validation.Valid;

import org.hibernate.validator.constraints.NotEmpty;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(Include.NON_EMPTY)
public class ScimGroupPatchRequest {

  public static final String PATCHOP_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

  private final Set<String> schemas;

  @NotEmpty
  @Valid
  private final List<ScimPatchOperation<List<ScimMemberRef>>> operations;

  @JsonCreator
  private ScimGroupPatchRequest(@JsonProperty("schemas") Set<String> schemas,
      @JsonProperty("operations") List<ScimPatchOperation<List<ScimMemberRef>>> operations) {

    this.schemas = schemas;
    if (operations == null) {
      throw new IllegalArgumentException("Operations list is null");
    }
    this.operations = operations;
  }

  private ScimGroupPatchRequest(Builder b) {

    this.schemas = b.schemas;
    this.operations = b.operations;
  }

  public Set<String> getSchemas() {

    return schemas;
  }

  public List<ScimPatchOperation<List<ScimMemberRef>>> getOperations() {

    return operations;
  }

  public static Builder builder() {

    return new Builder();
  }

  public static class Builder {

    private Set<String> schemas = new HashSet<String>();
    private List<ScimPatchOperation<List<ScimMemberRef>>> operations =
        new ArrayList<ScimPatchOperation<List<ScimMemberRef>>>();

    public Builder() {
      schemas.add(PATCHOP_SCHEMA);
    }

    public Builder add(List<ScimMemberRef> members) {

      operations.add((new ScimPatchOperation.Builder<List<ScimMemberRef>>()).add()
        .path("members")
        .value(members)
        .build());
      return this;
    }

    public Builder remove(List<ScimMemberRef> members) {

      operations.add((new ScimPatchOperation.Builder<List<ScimMemberRef>>()).remove()
        .path("members")
        .value(members)
        .build());
      return this;
    }

    public Builder replace(List<ScimMemberRef> members) {

      operations.add((new ScimPatchOperation.Builder<List<ScimMemberRef>>()).replace()
        .path("members")
        .value(members)
        .build());
      return this;
    }

    public ScimGroupPatchRequest build() {

      return new ScimGroupPatchRequest(this);
    }
  }
}
