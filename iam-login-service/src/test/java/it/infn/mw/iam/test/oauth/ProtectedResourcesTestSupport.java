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
package it.infn.mw.iam.test.oauth;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;

// Subclasses share one cached application context: every extra context adds to the test JVM
// metaspace, which is capped by jvm.test.args.
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
@ActiveProfiles({"h2-test"})
abstract class ProtectedResourcesTestSupport {

  static final String IAM = "http://localhost:8080";
  static final String DATA_API = "https://data.example.org/api";
  static final String MINIMAL_API = "https://minimal.example.org";
  static final String COMPUTE_API = "https://compute.example.org";

  static final String PROTECTED_RESOURCES = """
      protected-resources:
        - id: data-api
          resource: https://data.example.org/api
          scopes: [storage.read:/, storage.modify:/]
          name: Example data API
          documentation: https://data.example.org/docs
        - id: minimal
          resource: https://minimal.example.org
        - id: compute-api
          resource: https://compute.example.org
      """;

  static final Path PROTECTED_RESOURCES_FILE;

  static {
    try {
      PROTECTED_RESOURCES_FILE = Files.createTempFile("protected-resources", ".yml");
      Files.writeString(PROTECTED_RESOURCES_FILE, PROTECTED_RESOURCES);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  @DynamicPropertySource
  static void protectedResourcesFile(DynamicPropertyRegistry registry) {
    registry.add("iam.protected-resources-file.path", PROTECTED_RESOURCES_FILE::toString);
  }
}
