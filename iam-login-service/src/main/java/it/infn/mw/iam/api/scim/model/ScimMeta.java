/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
