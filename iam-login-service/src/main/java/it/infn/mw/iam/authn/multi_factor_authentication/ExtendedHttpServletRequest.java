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
package it.infn.mw.iam.authn.multi_factor_authentication;

import static it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference.AUTHENTICATION_METHOD_REFERENCE_CLAIM_STRING;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

/**
 * Represents an extended {@code HttpServletRequest} object. This is primarily used for including
 * information in an OAuth2 authorization request about the authentication method(s) used by the
 * user to sign in. These are ultimately passed to the token endpoint so they may be included in the
 * id_token received by the client.
 */
public final class ExtendedHttpServletRequest extends HttpServletRequestWrapper {

  private final Map<String, String[]> queryParameterMap;
  private final Charset requestEncoding;

  public ExtendedHttpServletRequest(HttpServletRequest request, String amrClaim) {
    super(request);
    Map<String, String[]> queryMap = getCommonQueryParamFromLegacy(request.getParameterMap());
    queryMap.put(AUTHENTICATION_METHOD_REFERENCE_CLAIM_STRING, new String[] {amrClaim});
    queryParameterMap = Collections.unmodifiableMap(queryMap);

    String encoding = request.getCharacterEncoding();
    requestEncoding = (encoding != null ? Charset.forName(encoding) : StandardCharsets.UTF_8);
  }

  private final Map<String, String[]> getCommonQueryParamFromLegacy(
      Map<String, String[]> paramMap) {
    Objects.requireNonNull(paramMap);

    Map<String, String[]> commonQueryParamMap = new LinkedHashMap<>(paramMap);

    return commonQueryParamMap;
  }

  @Override
  public String getParameter(String name) {
    String[] params = queryParameterMap.get(name);
    return params != null ? params[0] : null;
  }

  @Override
  public String[] getParameterValues(String name) {
    return queryParameterMap.get(name);
  }

  @Override
  public Map<String, String[]> getParameterMap() {
    return queryParameterMap; // unmodifiable to uphold the interface contract.
  }

  @Override
  public Enumeration<String> getParameterNames() {
    return Collections.enumeration(queryParameterMap.keySet());
  }

  @Override
  public String getQueryString() {
    // @see : https://stackoverflow.com/a/35831692/9869013
    // return queryParameterMap.entrySet().stream().flatMap(entry ->
    // Stream.of(entry.getValue()).map(value -> entry.getKey() + "=" +
    // value)).collect(Collectors.joining("&")); // without encoding !!
    return queryParameterMap.entrySet()
      .stream()
      .flatMap(entry -> encodeMultiParameter(entry.getKey(), entry.getValue(), requestEncoding))
      .collect(Collectors.joining("&"));
  }

  private Stream<String> encodeMultiParameter(String key, String[] values, Charset encoding) {
    return Stream.of(values).map(value -> encodeSingleParameter(key, value, encoding));
  }

  private String encodeSingleParameter(String key, String value, Charset encoding) {
    return urlEncode(key, encoding) + "=" + urlEncode(value, encoding);
  }

  private String urlEncode(String value, Charset encoding) {
    try {
      return URLEncoder.encode(value, encoding.name());
    } catch (UnsupportedEncodingException e) {
      throw new IllegalArgumentException("Cannot url encode " + value, e);
    }
  }

  @Override
  public ServletInputStream getInputStream() throws IOException {
    throw new UnsupportedOperationException("getInputStream() is not implemented in this "
        + HttpServletRequest.class.getSimpleName() + " wrapper");
  }

}
