package it.infn.mw.iam.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.audit.events.IamAuditApplicationEvent;

@Component
public class IamAuditEventLogger implements AuditEventLogger {
  
  public static final String AUDIT_MARKER_STRING = "AUDIT";
  public static final Marker AUDIT_MARKER = MarkerFactory.getMarker(AUDIT_MARKER_STRING);
  
  public static final Logger LOG = LoggerFactory.getLogger(AUDIT_MARKER_STRING);
  final AuditDataSerializer serializer;
  
  private IamAuditApplicationEvent lastEvent;
  
  @Autowired
  public IamAuditEventLogger(AuditDataSerializer serializer) {
    this.serializer = serializer;
  }

  @Override
  public void logAuditEvent(IamAuditApplicationEvent event) {
    lastEvent = event;
    LOG.info(AUDIT_MARKER, serializer.serialize(event));
  }
  
  public IamAuditApplicationEvent getLastEvent() {
    IamAuditApplicationEvent e = lastEvent;
    lastEvent = null;
    return e;
  }

}
