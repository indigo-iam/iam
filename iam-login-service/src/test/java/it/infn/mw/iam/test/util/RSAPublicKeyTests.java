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
package it.infn.mw.iam.test.util;

import static it.infn.mw.iam.test.SshKeyUtils.sshKeys;
import static java.lang.String.format;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import org.apache.commons.codec.digest.MessageDigestAlgorithms;
import org.junit.Test;

import it.infn.mw.iam.util.ssh.RSAPublicKeyUtils;

public class RSAPublicKeyTests {


  @Test
  public void testSHA256Fingerprint() {

    String fp = RSAPublicKeyUtils.getSHA256Fingerprint(sshKeys.get(0).key);
    assertThat(fp, equalTo(sshKeys.get(0).fingerprintSHA256));
    fp = RSAPublicKeyUtils.getSHA256Fingerprint(sshKeys.get(1).key);
    assertThat(fp, equalTo(sshKeys.get(1).fingerprintSHA256));
  }



  @Test
  public void testSHA26FingerprintIsAccepted() throws NoSuchAlgorithmException {

    final String test = "test";
    final String testBase64Encoded = Base64.getEncoder().encodeToString(test.getBytes());
    final String sha256fingerprint = Base64.getEncoder()
      .encodeToString(
          MessageDigest.getInstance(MessageDigestAlgorithms.SHA_256)
            .digest(test.getBytes()));


    assertThat(
        RSAPublicKeyUtils.getSHA256Fingerprint(format("preamble %s comment", testBase64Encoded)),
        is(sha256fingerprint));

    assertThat(RSAPublicKeyUtils.getSHA256Fingerprint(format("preamble %s", testBase64Encoded)),
        is(sha256fingerprint));

  }
}
