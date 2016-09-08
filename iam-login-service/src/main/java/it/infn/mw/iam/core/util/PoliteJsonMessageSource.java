package it.infn.mw.iam.core.util;

import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.mitre.openid.connect.config.ConfigurationPropertiesBean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.support.AbstractMessageSource;
import org.springframework.core.io.Resource;

import com.google.common.base.Splitter;
import com.google.gson.JsonElement;
import com.google.gson.JsonIOException;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

/**
 * This is a more polite {@link org.mitre.openid.connect.config.JsonMessageSource} that does not log
 * errors for unsupported locales.
 *
 */
public class PoliteJsonMessageSource extends AbstractMessageSource {

  // Logger for this class
  private static final Logger logger = LoggerFactory.getLogger(PoliteJsonMessageSource.class);

  private Resource baseDirectory;

  private Locale fallbackLocale = new Locale("en"); // US English is the
                                                    // fallback language

  private Map<Locale, List<JsonObject>> languageMaps = new HashMap<>();

  @Autowired
  private ConfigurationPropertiesBean config;

  @Override
  protected MessageFormat resolveCode(String code, Locale locale) {

    List<JsonObject> langs = getLanguageMap(locale);

    String value = getValue(code, langs);

    if (value == null) {
      // if we haven't found anything, try the default locale
      langs = getLanguageMap(fallbackLocale);
      value = getValue(code, langs);
    }

    if (value == null) {
      // if it's still null, return null
      return null;
    } else {
      // otherwise format the message
      return new MessageFormat(value, locale);
    }

  }

  /**
   * Get a value from the set of maps, taking the first match in order @param code @param
   * langs @return
   */
  private String getValue(String code, List<JsonObject> langs) {

    if (langs == null || langs.isEmpty()) {
      // no language maps, nothing to look up
      return null;
    }

    for (JsonObject lang : langs) {
      String value = getValue(code, lang);
      if (value != null) {
        // short circuit out of here if we find a match, otherwise keep going
        // through the list
        return value;
      }
    }

    // if we didn't find anything return null
    return null;
  }

  /**
   * Get a value from a single map @param code @param locale @param lang @return
   */
  private String getValue(String code, JsonObject lang) {

    // if there's no language map, nothing to look up
    if (lang == null) {
      return null;
    }

    JsonElement e = lang;

    Iterable<String> parts = Splitter.on('.').split(code);
    Iterator<String> it = parts.iterator();

    String value = null;

    while (it.hasNext()) {
      String p = it.next();
      if (e.isJsonObject()) {
        JsonObject o = e.getAsJsonObject();
        if (o.has(p)) {
          e = o.get(p); // found the next level
          if (!it.hasNext()) {
            // we've reached a leaf, grab it
            if (e.isJsonPrimitive()) {
              value = e.getAsString();
            }
          }
        } else {
          // didn't find it, stop processing
          break;
        }
      } else {
        // didn't find it, stop processing
        break;
      }
    }

    return value;

  }

  /**
   * @param locale @return
   */
  private List<JsonObject> getLanguageMap(Locale locale) {

    if (!languageMaps.containsKey(locale)) {
      try {
        List<JsonObject> set = new ArrayList<>();
        for (String namespace : config.getLanguageNamespaces()) {
          String filename = locale.getLanguage() + File.separator + namespace + ".json";

          Resource r = getBaseDirectory().createRelative(filename);

          logger.info("No locale loaded, trying to load from " + r);

          JsonParser parser = new JsonParser();
          JsonObject obj =
              (JsonObject) parser.parse(new InputStreamReader(r.getInputStream(), "UTF-8"));

          set.add(obj);
        }
        languageMaps.put(locale, set);
      } catch (JsonIOException | JsonSyntaxException | IOException e) {
        logger.debug("Unable to load locale: {}", e.getMessage());
      }
    }

    return languageMaps.get(locale);

  }

  /**
   * @return the baseDirectory
   */
  public Resource getBaseDirectory() {

    return baseDirectory;
  }

  /**
   * @param baseDirectory the baseDirectory to set
   */
  public void setBaseDirectory(Resource baseDirectory) {

    this.baseDirectory = baseDirectory;
  }

}
