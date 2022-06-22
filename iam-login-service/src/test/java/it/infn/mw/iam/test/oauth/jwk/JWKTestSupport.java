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
package it.infn.mw.iam.test.oauth.jwk;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.Charset;
import java.text.ParseException;

import org.mitre.jose.keystore.JWKSetKeyStore;

import com.nimbusds.jose.jwk.JWKSet;

import it.infn.mw.iam.core.web.jwk.IamJWKSetPublishingEndpoint;

public interface JWKTestSupport {

  String CLIENT_ID = "password-grant";
  String CLIENT_SECRET = "secret";
  String USERNAME = "test";
  String PASSWORD = "password";

  String JWK_ENDPOINT = "/" + IamJWKSetPublishingEndpoint.URL;

  String KS1_LOCATION = "/jwk/iam-keys.jwks";
  String KS2_LOCATION = "/jwk/other-keys.jwks";

  default JWKSet loadJWKSet(String location) throws IOException, ParseException {
    URL resource = JWTSigningServiceTests.class.getResource(location);
    try (InputStream stream = resource.openStream()) {
      String key =
          com.nimbusds.jose.util.IOUtils.readInputStreamToString(stream, Charset.defaultCharset());
      return JWKSet.parse(key);
    }
  }

  default JWKSetKeyStore loadKeystore(String location) throws IOException, ParseException {
    return new JWKSetKeyStore(loadJWKSet(location));
  }

}
