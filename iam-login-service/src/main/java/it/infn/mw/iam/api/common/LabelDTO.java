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
package it.infn.mw.iam.api.common;

import javax.annotation.Generated;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

import javax.validation.constraints.NotBlank;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class LabelDTO {

  // Matches simple domain names
  public static final String PREFIX_REGEXP = "^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\\.)+[A-Za-z]{2,6}$";

  public static final String NAME_REGEXP = "^[a-zA-Z][a-zA-Z0-9-_.]*$";

  @Size(max = 256, message = "invalid prefix length")
  @Pattern(regexp = PREFIX_REGEXP,
      message = "invalid prefix (does not match with regexp: '" + PREFIX_REGEXP + "')")
  private String prefix;

  @NotBlank(message="name is required")
  @Size(max = 64, message = "invalid name length")
  @Pattern(regexp = NAME_REGEXP,
      message = "invalid name (does not match with regexp: '" + NAME_REGEXP + "')")
  private String name;

  @Size(max = 64, message = "invalid value length")
  private String value;

  public LabelDTO() {}

  public LabelDTO(Builder builder) {
    this.prefix = builder.prefix;
    this.name = builder.name;
    this.value = builder.value;
  }

  public String getPrefix() {
    return prefix;
  }

  public void setPrefix(String prefix) {
    this.prefix = prefix;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getValue() {
    return value;
  }

  public void setValue(String value) {
    this.value = value;
  }

  @Override
  @Generated("eclipse")
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((name == null) ? 0 : name.hashCode());
    result = prime * result + ((prefix == null) ? 0 : prefix.hashCode());
    result = prime * result + ((value == null) ? 0 : value.hashCode());
    return result;
  }

  @Override
  @Generated("eclipse")
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    LabelDTO other = (LabelDTO) obj;
    if (name == null) {
      if (other.name != null)
        return false;
    } else if (!name.equals(other.name))
      return false;
    if (prefix == null) {
      if (other.prefix != null)
        return false;
    } else if (!prefix.equals(other.prefix))
      return false;
    if (value == null) {
      if (other.value != null)
        return false;
    } else if (!value.equals(other.value))
      return false;
    return true;
  }

  public static class Builder {
    private String prefix;
    private String name;
    private String value;

    public Builder prefix(String prefix) {
      this.prefix = prefix;
      return this;
    }

    public Builder name(String name) {
      this.name = name;
      return this;
    }

    public Builder value(String value) {
      this.value = value;
      return this;
    }

    public LabelDTO build() {
      return new LabelDTO(this);
    }
  }

  public static Builder builder() {
    return new Builder();
  }
}
