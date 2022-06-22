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
package it.infn.mw.iam.test.scim.me.patch;

import static it.infn.mw.iam.test.SshKeyUtils.sshKeys;
import static it.infn.mw.iam.test.X509Utils.x509Certs;

import it.infn.mw.iam.api.scim.model.ScimEmail;
import it.infn.mw.iam.api.scim.model.ScimName;
import it.infn.mw.iam.api.scim.model.ScimOidcId;
import it.infn.mw.iam.api.scim.model.ScimPhoto;
import it.infn.mw.iam.api.scim.model.ScimSamlId;
import it.infn.mw.iam.api.scim.model.ScimSshKey;
import it.infn.mw.iam.api.scim.model.ScimX509Certificate;

public class ScimMeEndpointUtils {

  protected final ScimName TESTUSER_NEWNAME =
      ScimName.builder().givenName("AAA").familyName("BBB").build();

  protected final ScimPhoto TESTUSER_NEWPHOTO =
      ScimPhoto.builder().value("http://fakesite.org/user.png").build();

  protected final ScimEmail TESTUSER_NEWEMAIL =
      ScimEmail.builder().email("fakeemail@iam.test").build();

  protected final ScimEmail ANOTHERUSER_EMAIL =
      ScimEmail.builder().email("test-100@test.org").build();

  protected final ScimOidcId TESTUSER_OIDCID =
      ScimOidcId.builder().issuer("ISS").subject("SUB").build();

  protected final ScimSamlId TESTUSER_SAMLID =
      ScimSamlId.builder().idpId("IDP").userId("UID").build();

  protected final ScimSshKey TESTUSER_SSHKEY =
      ScimSshKey.builder().display("KEY").value(sshKeys.get(0).key).primary(true).build();

  protected final ScimX509Certificate TESTUSER_X509CERT = ScimX509Certificate.builder()
    .display(x509Certs.get(0).display)
    .pemEncodedCertificate(x509Certs.get(0).certificate)
    .primary(true)
    .build();
}
