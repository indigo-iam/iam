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
package it.infn.mw.iam.rcauth.x509;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import eu.emi.security.authn.x509.impl.PEMCredential;
import eu.emi.security.authn.x509.proxy.ProxyCertificate;

public interface ProxyHelperService {

  public ProxyCertificate generateProxy(PEMCredential proxyCertificate, long lifetimeInSecs);

  public ProxyCertificate generateProxy(X509Certificate cert, PrivateKey key);

  public String proxyCertificateToPemString(ProxyCertificate proxy);

  public PEMCredential credentialFromPemString(String pemString);

}
