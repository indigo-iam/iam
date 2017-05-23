package it.infn.mw.iam.api.scim.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

@JsonInclude(Include.NON_EMPTY)
public class ScimAuthority {

  private final long id;
  private final String authority;
  
  @JsonCreator
  private ScimAuthority(@JsonProperty("id") long id, @JsonProperty("authority") String authority) {

	this.id = id;
	this.authority = authority;
  }

  
  public long getId() {
  
    return id;
  }

  
  public String getAuthority() {
  
    return authority;
  }
  
  private ScimAuthority(Builder b) {
	
	this.id = b.id;
	this.authority = b.authority;
  }

  public static Builder builder() {

    return new Builder();
  }

  public static class Builder {
	
	private long id;
	private String authority;
	
	public Builder id(long id) {
	  
	  this.id = id;
	  return this;
	}
	
	public Builder authority(String authority) {
	  
	  this.authority = authority;
	  return this;
	}
	
	public ScimAuthority build() {
	  
	  return new ScimAuthority(this);
	}
  }
}
