package it.infn.mw.iam.audit;

import it.infn.mw.iam.audit.events.IamAuditApplicationEvent;

public interface AuditDataSerializer {

  public String serialize(IamAuditApplicationEvent event);
  
}
