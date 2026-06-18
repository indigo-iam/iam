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
package it.infn.mw.iam.api.client.registration.validation;

import static java.lang.String.format;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Objects;
import java.util.Set;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.mitre.openid.connect.service.BlacklistedSiteService;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.api.common.client.RegisteredClientDTO;

@Component
@Scope("prototype")
public class ValidRedirectURIsValidator
    implements ConstraintValidator<ValidRedirectURIs, RegisteredClientDTO> {

  private static final Set<String> ALLOWED_SCHEMES = Set.of("https", "http");
  private static final Set<String> ALLOWED_HOSTS_FOR_HTTP =
      Set.of("localhost", "127.0.0.1", "[::1]", "[0:0:0:0:0:0:0:1]");
  private static final Set<String> ALLOWED_REDIRECT_URIS =
      Set.of("edu.kit.data.oidc-agent:/redirect");
  private final BlacklistedSiteService denyListService;

  public ValidRedirectURIsValidator(BlacklistedSiteService denyListService) {
    this.denyListService = denyListService;
  }

  private boolean invalid(ConstraintValidatorContext context, String message) {
    context.disableDefaultConstraintViolation();
    context.buildConstraintViolationWithTemplate(message).addConstraintViolation();
    return false;
  }

  @Override
  public boolean isValid(RegisteredClientDTO value, ConstraintValidatorContext context) {
    if (Objects.isNull(value.getRedirectUris())) {
      return true;
    }

    for (String uri : value.getRedirectUris()) {
      URI parsedUri;
      try {
        parsedUri = new URI(uri);
      } catch (URISyntaxException e) {
        return invalid(context, "Invalid redirect URI");
      }

      if (ALLOWED_REDIRECT_URIS.contains(uri)) {
        continue;
      }

      String scheme = parsedUri.getScheme();
      if (scheme == null || !ALLOWED_SCHEMES.contains(scheme.toLowerCase())) {
        return invalid(context, format("Invalid redirect URI scheme: %s", scheme));
      }

      if ("http".equalsIgnoreCase(scheme)
          && !ALLOWED_HOSTS_FOR_HTTP.contains(parsedUri.getHost())) {
        return invalid(context, "Plain http redirect URIs are only allowed for loopback");
      }

      if (parsedUri.getFragment() != null) {
        return invalid(context, "Invalid redirect URI: contains a fragment");
      }

      if (denyListService.isBlacklisted(uri)) {
        return invalid(context, format("Invalid redirect URI: %s is not allowed", uri));
      }
    }
    return true;
  }
}
