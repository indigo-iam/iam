package it.infn.mw.iam.authn.util;

import javax.servlet.http.HttpSession;

public class SessionUtils {

  /**
   * Get the named stored session variable as a string. Return null if not found or not a string.
   *
   * @param session
   *
   * @param key
   *
   * @return
   */
  public static String getStoredSessionString(HttpSession session, String key) {

    Object o = session.getAttribute(key);
    if (o != null && o instanceof String) {
      return (String) o;
    } else {
      return null;
    }
  }

}
