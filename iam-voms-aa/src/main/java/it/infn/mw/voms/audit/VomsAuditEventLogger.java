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
package it.infn.mw.voms.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;
import org.springframework.stereotype.Component;

import it.infn.mw.voms.audit.events.VomsAuditApplicationEvent;

@Component
public class VomsAuditEventLogger implements AuditEventLogger {

  public static final String AUDIT_MARKER_STRING = "AUDIT";
  public static final Marker AUDIT_MARKER = MarkerFactory.getMarker(AUDIT_MARKER_STRING);

  public static final Logger LOG = LoggerFactory.getLogger(AUDIT_MARKER_STRING);
  final AuditDataSerializer serializer;

  public VomsAuditEventLogger(AuditDataSerializer serializer) {
    this.serializer = serializer;
  }

  @Override
  public void logAuditEvent(VomsAuditApplicationEvent event) {
    if (LOG.isInfoEnabled()) {
      final String serializedEvent = serializer.serialize(event);
      LOG.info(AUDIT_MARKER, serializedEvent);
    }
  }
}
