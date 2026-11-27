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
package it.infn.mw.iam.jwkfallback;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.MediaTypeFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;



@RestController
class FallbackInfoController {

  private final String page;

  FallbackInfoController(ResourceLoader loader,
      @Value ("${iam.logo.url:}") String logoUrl,
      @Value("${iam.organisation.name:INDIGO IAM}") String organisationName) throws IOException {

    String html = StreamUtils.copyToString(
        new ClassPathResource("fallback-app/fallback-info.html").getInputStream(),
        StandardCharsets.UTF_8);
    this.page = html.replace("{{LOGO}}", logoTag(loader, logoUrl, organisationName));
  }

  @GetMapping("/fallback-info")
  ResponseEntity<String> info() {
    return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
        .header(HttpHeaders.RETRY_AFTER, "300")
        .cacheControl(CacheControl.noStore())
        .contentType(new MediaType("text", "html", StandardCharsets.UTF_8))
        .body(page);
  }

  private static String logoTag(ResourceLoader loader, String logoUrl, String alt) {
    if (logoUrl.isBlank()) {
      return "";
    }
    String src = logoUrl;
    if (!logoUrl.startsWith("http://") && !logoUrl.startsWith("https://")) {
      try {
        Resource logo = loader.getResource(logoUrl);
        String mime = MediaTypeFactory.getMediaType(logo).orElse(MediaType.IMAGE_PNG).toString();
        src = "data:" + mime + ";base64,"
            + Base64.getEncoder().encodeToString(StreamUtils.copyToByteArray(logo.getInputStream()));
      } catch (IOException e) {
        return ""; // a missing logo must not stop the fallback page from working
      }
    }
    return "<img class=\"logo\" alt=\"" + HtmlUtils.htmlEscape(alt)
        + "\" src=\"" + HtmlUtils.htmlEscape(src) + "\">";
  }
}