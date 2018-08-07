/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2018
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
package it.infn.mw.iam.config.oidc;

import org.springframework.stereotype.Component;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(Include.NON_EMPTY)
@Component
public class OidcLoginButton {

  public static final Integer DEFAULT_ORDER = 0;
  public static final String DEFAULT_STYLE = "openid";
  public static final String DEFAULT_TEXT = "Sign-in with OIDC";

  private Integer order = DEFAULT_ORDER;
  private String text = DEFAULT_TEXT;
  private String style = DEFAULT_STYLE;

  public OidcLoginButton() {
    // empty constructor
  }

  @JsonCreator
  public OidcLoginButton(@JsonProperty("order") Integer order, @JsonProperty("text") String text,
      @JsonProperty("style") String style) {
    super();
    this.order = order;
    this.text = text;
    this.style = style;
  }

  public Integer getOrder() {
    return order;
  }

  public void setOrder(Integer order) {
    this.order = order;
  }

  public String getText() {
    return text;
  }

  public void setText(String text) {
    this.text = text;
  }

  public String getStyle() {
    return style;
  }

  public void setStyle(String style) {
    this.style = style;
  }
}
