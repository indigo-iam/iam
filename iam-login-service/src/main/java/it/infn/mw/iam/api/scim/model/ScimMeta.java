package it.infn.mw.iam.api.scim.model;

import java.util.Date;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.google.common.base.Preconditions;

import it.infn.mw.iam.api.scim.controller.utils.JsonDateSerializer;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class ScimMeta {

  private final String resourceType;

  @JsonSerialize(using = JsonDateSerializer.class)
  private final Date created;

  @JsonSerialize(using = JsonDateSerializer.class)
  private final Date lastModified;

  private final String location;
  private final String version;

  @JsonCreator
  private ScimMeta(@JsonProperty("created") Date created,
      @JsonProperty("lastModified") Date lastModified, @JsonProperty("location") String location,
      @JsonProperty("version") String version, @JsonProperty("resourceType") String resourceType) {

    this.created = created;
    this.lastModified = lastModified;
    this.location = location;
    this.version = version;
    this.resourceType = resourceType;

  }

  private ScimMeta(Builder b) {
    this.resourceType = b.resourceType;
    this.created = b.created;
    this.lastModified = b.lastModified;
    this.location = b.location;
    this.version = b.version;
  }

  public String getResourceType() {

    return resourceType;
  }

  public Date getCreated() {

    return created;
  }

  public Date getLastModified() {

    return lastModified;
  }

  public String getLocation() {

    return location;
  }

  public String getVersion() {

    return version;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((created == null) ? 0 : created.hashCode());
    result = prime * result + ((lastModified == null) ? 0 : lastModified.hashCode());
    result = prime * result + ((location == null) ? 0 : location.hashCode());
    result = prime * result + ((resourceType == null) ? 0 : resourceType.hashCode());
    result = prime * result + ((version == null) ? 0 : version.hashCode());
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
    ScimMeta other = (ScimMeta) obj;
    if (created == null) {
      if (other.created != null)
        return false;
    } else if (!created.equals(other.created))
      return false;
    if (lastModified == null) {
      if (other.lastModified != null)
        return false;
    } else if (!lastModified.equals(other.lastModified))
      return false;
    if (location == null) {
      if (other.location != null)
        return false;
    } else if (!location.equals(other.location))
      return false;
    if (resourceType == null) {
      if (other.resourceType != null)
        return false;
    } else if (!resourceType.equals(other.resourceType))
      return false;
    if (version == null) {
      if (other.version != null)
        return false;
    } else if (!version.equals(other.version))
      return false;
    return true;
  }

  public static Builder builder(Date created, Date lastModified) {

    return new Builder(created, lastModified);
  }

  public static class Builder {

    private final Date created;
    private final Date lastModified;
    private String location;
    private String version;
    private String resourceType;

    public Builder(Date created, Date lastModified) {
      this.created = created;
      this.lastModified = lastModified;
    }

    public Builder location(String location) {

      this.location = location;
      return this;
    }

    public Builder version(String version) {

      this.version = version;
      return this;
    }

    public Builder resourceType(String resourceType) {

      this.resourceType = resourceType;
      return this;
    }

    public ScimMeta build() {

      Preconditions.checkNotNull(resourceType, "resourceType must be non-null");
      Preconditions.checkNotNull(location, "location must be non-null");

      return new ScimMeta(this);
    }
  }
}
