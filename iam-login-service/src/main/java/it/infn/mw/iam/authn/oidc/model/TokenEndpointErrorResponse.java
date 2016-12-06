package it.infn.mw.iam.authn.oidc.model;

import java.util.Map;

import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.collect.Maps;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class TokenEndpointErrorResponse {

  String error;

  @JsonProperty("error_description")
  String errorDescription;

  @JsonProperty("error_uri")
  String errorUri;

  @JsonIgnore
  Map<String, Object> unknownFields = Maps.newHashMap();

  public TokenEndpointErrorResponse() {}

  @JsonCreator
  public TokenEndpointErrorResponse(@JsonProperty("error") String error,
      @JsonProperty("error_description") String errorDescription,
      @JsonProperty("error_uri") String errorUri) {

    this.error = error;
    this.errorDescription = errorDescription;
    this.errorUri = errorUri;
  }

  public String getError() {
    return error;
  }

  public void setError(String error) {
    this.error = error;
  }

  public String getErrorDescription() {
    return errorDescription;
  }

  public void setErrorDescription(String errorDescription) {
    this.errorDescription = errorDescription;
  }

  public String getErrorUri() {
    return errorUri;
  }

  public void setErrorUri(String errorUri) {
    this.errorUri = errorUri;
  }

  @JsonAnySetter
  public void handleUnkwownFields(String key, Object value) {
    unknownFields.put(key, value);
  }

}
