package it.infn.mw.iam.audit;

import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class IamAuditUtils {

  public static final String NULL_PRINCIPAL = "<unknown>";
  public static final String AUTHN_CATEGORY = "AUTHENTICATION";
  public static final String AUTHZ_CATEGORY = "AUTHORIZATION";

  public static String printAuditData(Map<String, Object> data) {
    String json = "";
    try {
      json = new ObjectMapper().writeValueAsString(data);
    } catch (JsonProcessingException e) {
      json = "Data parsing error: " + e.getMessage();
    }
    return json;
  }
}
