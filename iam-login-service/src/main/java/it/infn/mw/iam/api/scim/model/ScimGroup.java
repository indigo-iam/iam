package it.infn.mw.iam.api.scim.model;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import javax.validation.Valid;

import org.hibernate.validator.constraints.NotBlank;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonFilter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(Include.NON_EMPTY)
@JsonFilter("attributeFilter")
public final class ScimGroup extends ScimResource {

  public static final String GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group";
  public static final String RESOURCE_TYPE = "Group";

  @NotBlank
  private final String displayName;

  @Valid
  private final Set<ScimMemberRef> members;

  @JsonCreator
  private ScimGroup(@JsonProperty("id") String id, @JsonProperty("externalId") String externalId,
      @JsonProperty("meta") ScimMeta meta, @JsonProperty("schemas") Set<String> schemas,
      @JsonProperty("displayName") String displayName,
      @JsonProperty("members") Set<ScimMemberRef> members) {

    super(id, externalId, meta, schemas);
    this.displayName = displayName;
    this.members = (members != null ? members : Collections.<ScimMemberRef>emptySet());
  }

  private ScimGroup(Builder b) {

    super(b);
    this.displayName = b.displayName;
    this.members = b.members;
  }

  public String getDisplayName() {

    return displayName;
  }

  public Set<ScimMemberRef> getMembers() {

    return members;
  }

  public static Builder builder(String groupName) {

    return new Builder(groupName);
  }

  public static class Builder extends ScimResource.Builder<ScimGroup> {

    private String displayName;
    private Set<ScimMemberRef> members = new HashSet<ScimMemberRef>();

    public Builder(String displayName) {
      super();
      schemas.add(GROUP_SCHEMA);
      this.displayName = displayName;
    }

    public Builder id(String id) {

      this.id = id;
      return this;
    }

    public Builder meta(ScimMeta meta) {

      this.meta = meta;
      return this;
    }

    public Builder setMembers(Set<ScimMemberRef> members) {

      this.members = members;
      return this;
    }

    public ScimGroup build() {

      return new ScimGroup(this);
    }
  }
}
