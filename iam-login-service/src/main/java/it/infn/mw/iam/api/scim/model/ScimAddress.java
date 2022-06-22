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

import javax.annotation.Generated;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class ScimAddress {

  public enum ScimAddressType {
    work, home, other;
  }

  private final ScimAddressType type;

  private final String formatted;
  private final String streetAddress;
  private final String locality;
  private final String region;
  private final String postalCode;
  private final String country;

  private final Boolean primary;

  @JsonCreator
  private ScimAddress(@JsonProperty("type") ScimAddressType type,
      @JsonProperty("formatted") String formatted,
      @JsonProperty("streetAddress") String streetAddress,
      @JsonProperty("locality") String locality, @JsonProperty("region") String region,
      @JsonProperty("postalCode") String postalCode, @JsonProperty("country") String country,
      @JsonProperty("primary") Boolean primary) {

    this.type = type;
    this.formatted = formatted;
    this.streetAddress = streetAddress;
    this.locality = locality;
    this.region = region;
    this.postalCode = postalCode;
    this.country = country;
    this.primary = primary;
  }

  private ScimAddress(Builder b) {
    this.formatted = b.formatted;
    this.streetAddress = b.streetAddress;
    this.locality = b.locality;
    this.region = b.region;
    this.postalCode = b.postalCode;
    this.country = b.country;
    this.primary = b.primary;
    this.type = b.type;
  }

  public ScimAddressType getType() {

    return type;
  }

  public String getFormatted() {

    return formatted;
  }

  public String getStreetAddress() {

    return streetAddress;
  }

  public String getLocality() {

    return locality;
  }

  public String getRegion() {

    return region;
  }

  public String getPostalCode() {

    return postalCode;
  }

  public String getCountry() {

    return country;
  }

  public Boolean getPrimary() {

    return primary;
  }

  @Generated("Eclipse")
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((country == null) ? 0 : country.hashCode());
    result = prime * result + ((formatted == null) ? 0 : formatted.hashCode());
    result = prime * result + ((locality == null) ? 0 : locality.hashCode());
    result = prime * result + ((postalCode == null) ? 0 : postalCode.hashCode());
    result = prime * result + ((primary == null) ? 0 : primary.hashCode());
    result = prime * result + ((region == null) ? 0 : region.hashCode());
    result = prime * result + ((streetAddress == null) ? 0 : streetAddress.hashCode());
    result = prime * result + ((type == null) ? 0 : type.hashCode());
    return result;
  }

  @Generated("Eclipse")
  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    ScimAddress other = (ScimAddress) obj;
    if (country == null) {
      if (other.country != null)
        return false;
    } else if (!country.equals(other.country))
      return false;
    if (formatted == null) {
      if (other.formatted != null)
        return false;
    } else if (!formatted.equals(other.formatted))
      return false;
    if (locality == null) {
      if (other.locality != null)
        return false;
    } else if (!locality.equals(other.locality))
      return false;
    if (postalCode == null) {
      if (other.postalCode != null)
        return false;
    } else if (!postalCode.equals(other.postalCode))
      return false;
    if (primary == null) {
      if (other.primary != null)
        return false;
    } else if (!primary.equals(other.primary))
      return false;
    if (region == null) {
      if (other.region != null)
        return false;
    } else if (!region.equals(other.region))
      return false;
    if (streetAddress == null) {
      if (other.streetAddress != null)
        return false;
    } else if (!streetAddress.equals(other.streetAddress))
      return false;
    if (type != other.type)
      return false;
    return true;
  }

  public static Builder builder() {

    return new Builder();
  }

  public static class Builder {

    private ScimAddressType type = ScimAddressType.work;

    private String formatted;
    private String streetAddress;
    private String locality;
    private String region;
    private String postalCode;
    private String country;
    private boolean primary = true;

    public Builder formatted(String formatted) {

      this.formatted = formatted;
      return this;
    }

    public Builder streetAddress(String streetAddress) {

      this.streetAddress = streetAddress;
      return this;
    }

    public Builder locality(String locality) {

      this.locality = locality;
      return this;
    }

    public Builder region(String region) {

      this.region = region;
      return this;
    }

    public Builder postalCode(String postalCode) {

      this.postalCode = postalCode;
      return this;
    }

    public Builder country(String country) {

      this.country = country;
      return this;
    }

    public ScimAddress build() {

      return new ScimAddress(this);
    }
  }

}
