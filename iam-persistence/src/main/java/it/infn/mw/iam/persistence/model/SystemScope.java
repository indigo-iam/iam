
package it.infn.mw.iam.persistence.model;

import java.util.Objects;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;

import org.hibernate.validator.constraints.Length;

@Entity
@Table(name = "system_scope")
public class SystemScope {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "id")
  private Long id;

  @NotNull
  @Column(name = "scope", unique = true)
  @Length(max = 256)
  private String value;

  @Column(name = "description")
  @Length(max = 4096)
  private String description;

  @Column(name = "icon")
  @Length(max = 256)
  private String icon;

  @NotNull
  @Column(name = "default_scope")
  private boolean defaultScope = false;

  @NotNull
  @Column(name = "restricted")
  private boolean restricted = false;

  @NotNull
  @Column(name = "structured")
  private boolean structured = false;

  @Column(name = "structured_param_description")
  @Length(max = 256)
  private String structuredDescription;

  public SystemScope(String value) {
    setValue(value);
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

  public String getStructuredDescription() {
    return structuredDescription;
  }

  public void setStructuredDescription(String structuredDescription) {
    this.structuredDescription = structuredDescription;
  }

  @Override
  public int hashCode() {
    return Objects.hash(value);
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
    return Objects.equals(value, other.value);
  }

  @Override
  public String toString() {
    return "SystemScope [id=" + id + ", value=" + value + ", description=" + description + ", icon="
        + icon + ", defaultScope=" + defaultScope + ", restricted=" + restricted + "]";
  }

}
