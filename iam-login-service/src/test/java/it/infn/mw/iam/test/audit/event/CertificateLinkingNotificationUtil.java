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
package it.infn.mw.iam.test.audit.event;

public interface CertificateLinkingNotificationUtil {

  default String getLinkMessage(String name, String username, String email, String subjectDn,
      String issuerDn, String organisationName) {
    return String.format(
        "The following user has linked a certificate to their account. %n%nName: %s%nUsername: %s%nEmail: %s%nSubjectDN: %s%nIssuerDN: %s%n%nThe %s registration service%n",
        name, username, email, subjectDn, issuerDn, organisationName);
  }

  default String getUnLinkMessage(String name, String username, String email, String subjectDn,
      String issuerDn, String organisationName) {
    return String.format(
        "The following user has removed a previously linked a certificate from their account. %n%nName: %s%nUsername: %s%nEmail: %s%nSubjectDN: %s%nIssuerDN: %s%n%nThe %s registration service%n",
        name, username, email, subjectDn, issuerDn, organisationName);
  }
}
