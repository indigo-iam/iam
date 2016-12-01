package it.infn.mw.iam.api.scim.model;

import java.util.HashSet;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonProperty;

public abstract class ScimResource {

  private final String id;
  private final String externalId;
  private final ScimMeta meta;

  @JsonProperty(required = true)
  private final Set<String> schemas;

  protected ScimResource(@JsonProperty("id") String id,
      @JsonProperty("externalId") String externalId, @JsonProperty("meta") ScimMeta meta,
      @JsonProperty("schemas") Set<String> schemas) {

    this.id = id;
    this.externalId = externalId;
    this.meta = meta;
    this.schemas = schemas;

  }

  protected ScimResource(Builder<?> b) {
    id = b.id;
    externalId = b.externalid;
    meta = b.meta;
    schemas = b.schemas;
  }

  public String getId() {

    return id;
  }

  public String getExternalId() {

    return externalId;
  }

  public ScimMeta getMeta() {

    return meta;
  }

  public Set<String> getSchemas() {

    return schemas;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((id == null) ? 0 : id.hashCode());
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
    ScimResource other = (ScimResource) obj;
    if (id == null) {
      if (other.id != null)
        return false;
    } else if (!id.equals(other.id))
      return false;
    return true;
  }

  public static abstract class Builder<T extends ScimResource> {

    protected String externalid;
    protected String id;
    protected ScimMeta meta;
    protected Set<String> schemas = new HashSet<>();

    public abstract T build();

  }
}
