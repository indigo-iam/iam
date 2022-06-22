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
package it.infn.mw.voms.aa.ac;

import static it.infn.mw.voms.aa.ac.ACGeneratorUtils.computeRandomSerialNumber;
import static java.util.Objects.isNull;

import java.io.IOException;
import java.math.BigInteger;
import java.util.List;

import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.italiangrid.voms.asn1.VOMSACGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Lists;

import eu.emi.security.authn.x509.impl.PEMCredential;
import it.infn.mw.voms.aa.VOMSRequestContext;

public class ThreadLocalACGenerator implements ACGenerator {

  public static final Logger LOG = LoggerFactory.getLogger(ThreadLocalACGenerator.class);

  private ThreadLocal<VOMSACGenerator> acGenerator;

  @Override
  public void configure(PEMCredential aaCredential) {
    acGenerator = ThreadLocal.withInitial(() -> new VOMSACGenerator(aaCredential));
  }

  @Override
  public byte[] generateVOMSAC(VOMSRequestContext context) throws IOException {

    VOMSACGenerator generator = acGenerator.get();

    if (isNull(generator)) {
      throw new IllegalStateException("AC generator is not configured!");
    }

    BigInteger serialNo = computeRandomSerialNumber();

    List<String> issuedFqans = Lists.newArrayList(context.getResponse().getIssuedFQANs());

    X509AttributeCertificateHolder ac = generator.generateVOMSAttributeCertificate(issuedFqans,
        context.getResponse().getIssuedGAs(), context.getResponse().getTargets(),
        context.getRequest().getHolderCert(), serialNo, context.getResponse().getNotBefore(),
        context.getResponse().getNotAfter(), context.getVOName(), context.getHost(),
        context.getPort());

    return ac.getEncoded();
  }

}
