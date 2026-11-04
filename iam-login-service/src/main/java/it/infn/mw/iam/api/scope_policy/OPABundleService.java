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
package it.infn.mw.iam.api.scope_policy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPOutputStream;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.api.scope_policy.ScopePolicyController.OpaPolicies;
import it.infn.mw.iam.persistence.model.IamScopePolicy;
import it.infn.mw.iam.persistence.model.IamScopePolicy.MatchingPolicy;

@Service
public class OPABundleService {

  private final ScopePolicyService policyService;
  private final IamScopePolicyConverter converter;
  private final ObjectMapper objectMapper;

  public OPABundleService(ScopePolicyService policyService, IamScopePolicyConverter converter,
      ObjectMapper objectMapper) {
    this.policyService = policyService;
    this.converter = converter;
    this.objectMapper = objectMapper;
  }

  // Records don't compare array contents, so two bundles with the same bytes are not equal.
  // Not a problem here: OpaBundle only carries the response, it is never compared.
  @SuppressWarnings("java:S6218")
  public record OpaBundle(byte[] content, String etag) {}


  public OpaPolicies getPolicies() {
    Iterable<IamScopePolicy> policies = policyService.findAllScopePolicies();
    List<OpaPolicies.OpaPolicy> dtos = new ArrayList<>();

    policies.forEach(p -> {
      if (!p.getMatchingPolicy().equals(MatchingPolicy.REGEXP)) {
        dtos.add(converter.toOpaPolicyDTO(p));
      }
    });

    return new OpaPolicies(dtos);
  }

  public OpaBundle buildBundle() throws IOException {
    byte[] data = objectMapper.writeValueAsBytes(getPolicies());
    String etag = sha256Hex(data);

    Map<String, byte[]> files = new LinkedHashMap<>();
    files.put("data.json", data);
    files.put(".manifest", objectMapper.writeValueAsBytes(Map.of("roots", List.of("policies"))));

    return new OpaBundle(tarGzip(files), etag);
  }

  private static String sha256Hex(byte[] content) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 algorithm not available", e);
    }
  }

  private byte[] tarGzip(Map<String, byte[]> files) throws IOException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();

    try (
      GZIPOutputStream gzip = new GZIPOutputStream(output);
      TarArchiveOutputStream tar = new TarArchiveOutputStream(gzip);
    ) {
      for (Map.Entry<String, byte[]> file : files.entrySet()) {
        TarArchiveEntry entry = new TarArchiveEntry(file.getKey());

        entry.setSize(file.getValue().length);
        tar.putArchiveEntry(entry);
        tar.write(file.getValue());
        tar.closeArchiveEntry();
      }
    }

    return output.toByteArray();
  }
}
