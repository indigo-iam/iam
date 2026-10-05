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

import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.api.common.client.TokenEndpointAuthenticationMethod;
import it.infn.mw.iam.core.oauth.consent.BlockedUriService;

@Component
@Scope("prototype")
public class ValidPostLogoutRedirectURIsValidator
    implements ConstraintValidator<ValidPostLogoutRedirectURIs, RegisteredClientDTO> {

  private static final Set<String> ALLOWED_SCHEMES = Set.of("https", "http");
  private static final Set<String> ALLOWED_HTTP_HOSTS =
      Set.of("localhost", "127.0.0.1", "[::1]", "[0:0:0:0:0:0:0:1]");
  private final BlockedUriService denyListService;

  public ValidPostLogoutRedirectURIsValidator(BlockedUriService denyListService) {
    this.denyListService = denyListService;
  }

  private boolean invalid(ConstraintValidatorContext context, String message) {
    context.disableDefaultConstraintViolation();
    context.buildConstraintViolationWithTemplate(message).addConstraintViolation();
    return false;
  }

  @Override
  public boolean isValid(RegisteredClientDTO value, ConstraintValidatorContext context) {

    if (!Objects.isNull(value.getPostLogoutRedirectUris())) {
      for (String uri : value.getPostLogoutRedirectUris()) {
        if (!isValid(uri, value, context)) {
          return false;
        }
      }
    }
    return true;
  }

  private boolean isValid(String uri, RegisteredClientDTO value,
      ConstraintValidatorContext context) {

    URI parsedUri;

    try {
      parsedUri = new URI(uri);
    } catch (URISyntaxException e) {
      return invalid(context, "Invalid post logout redirect URI");
    }

    if (!parsedUri.isAbsolute()) {
      return invalid(context, "Post logout redirect URI must be absolute");
    }

    String scheme = parsedUri.getScheme();
    if (scheme == null || !ALLOWED_SCHEMES.contains(scheme.toLowerCase())) {
      return invalid(context, format("Invalid post logout redirect URI scheme: %s", scheme));
    }

    boolean isHttp = "http".equalsIgnoreCase(scheme);
    boolean isLoopback = ALLOWED_HTTP_HOSTS.contains(parsedUri.getHost());
    boolean isPublicClient =
        TokenEndpointAuthenticationMethod.none.equals(value.getTokenEndpointAuthMethod());

    if (isHttp && isPublicClient) {
      return invalid(context,
          "Plain http post logout redirect URIs are only allowed for confidential clients");
    }

    if (isHttp && !isLoopback) {
      return invalid(context,
          "Plain http post logout redirect URIs are only allowed for loopback hosts");
    }

    if (parsedUri.getFragment() != null) {
      return invalid(context, "Invalid redirect URI: contains a fragment");
    }

    if (denyListService.isBlockedUri(uri)) {
      return invalid(context, format("Invalid post logout redirect URI: %s is not allowed", uri));
    }

    return true;
  }
}
