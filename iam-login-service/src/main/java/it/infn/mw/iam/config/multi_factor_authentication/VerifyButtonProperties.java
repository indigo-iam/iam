package it.infn.mw.iam.config.multi_factor_authentication;

import javax.validation.constraints.NotBlank;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

@JsonInclude(Include.NON_EMPTY)
public class VerifyButtonProperties {
  private String text;

  private String title;

  @NotBlank
  private String style = "btn-verify";

  private boolean visible = true;

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

  public boolean isVisible() {
    return visible;
  }

  public void setVisible(boolean visible) {
    this.visible = visible;
  }

  public String getTitle() {
    return title;
  }

  public void setTitle(String title) {
    this.title = title;
  }
}
