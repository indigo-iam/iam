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
package it.infn.mw.iam.persistence.model;

import java.io.Serializable;
import java.util.Objects;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "system_scope")
public class SystemScope implements Serializable {

  private static final long serialVersionUID = 526486902416173479L;

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "id")
  private Long id;

  @Column(name = "scope", unique = true, length = 256, nullable = false)
  private String value;

  @Column(name = "description", length = 4096)
  private String description;

  @Column(name = "icon", length = 256)
  private String icon;

  @Column(name = "default_scope", nullable = false)
  private boolean defaultScope;

  @Column(name = "restricted", nullable = false)
  private boolean restricted;

  @Column(name = "structured", nullable = false)
  private boolean structured;

  public SystemScope() {
    this.defaultScope = false;
    this.restricted = false;
    this.structured = false;
  }

  public SystemScope(String value) {
    this();
    this.value = value;
  }

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public String getValue() {
    return value;
  }

  public void setValue(String value) {
    this.value = value;
  }

  public String getDescription() {
    return description;
  }

  public void setDescription(String description) {
    this.description = description;
  }

  public String getIcon() {
    return icon;
  }

  public void setIcon(String icon) {
    this.icon = icon;
  }

  public boolean isDefaultScope() {
    return defaultScope;
  }

  public void setDefaultScope(boolean defaultScope) {
    this.defaultScope = defaultScope;
  }

  public boolean isRestricted() {
    return restricted;
  }

  public void setRestricted(boolean restricted) {
    this.restricted = restricted;
  }

  public boolean isStructured() {
    return structured;
  }

  public void setStructured(boolean structured) {
    this.structured = structured;
  }

  @Override
  public int hashCode() {
    return Objects.hash(defaultScope, description, icon, id, restricted, structured, value);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    SystemScope other = (SystemScope) obj;
    return defaultScope == other.defaultScope && Objects.equals(description, other.description)
        && Objects.equals(icon, other.icon) && Objects.equals(id, other.id)
        && restricted == other.restricted && structured == other.structured
        && Objects.equals(value, other.value);
  }

  @Override
  public String toString() {
    return "SystemScope [id=" + id + ", value=" + value + ", description=" + description + ", icon="
        + icon + ", defaultScope=" + defaultScope + ", restricted=" + restricted + ", structured="
        + structured + "]";
  }

}
