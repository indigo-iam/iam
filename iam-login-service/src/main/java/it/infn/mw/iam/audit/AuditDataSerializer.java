package it.infn.mw.iam.audit;

import java.util.Map;

public interface AuditDataSerializer {

  public String serialize(Map<String, Object> data);
  
}
