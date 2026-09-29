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

import it.infn.mw.iam.config.IamProperties;

@SuppressWarnings("deprecation")
public class PoliteJsonMessageSource extends AbstractMessageSource {

  private static final Logger LOG = LoggerFactory.getLogger(PoliteJsonMessageSource.class);

  private Resource baseDirectory;

  private Locale fallbackLocale = new Locale("en");

  private Map<Locale, List<JsonObject>> languageMaps = new HashMap<>();

  @Autowired
  private IamProperties config;

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
      return null;
    }
    return new MessageFormat(value, locale);
  }

  private String getValue(String code, List<JsonObject> langs) {

    if (langs == null || langs.isEmpty()) {
      return null;
    }

    for (JsonObject lang : langs) {
      String value = getValue(code, lang);
      if (value != null) {
        return value;
      }
    }
    return null;
  }

  private String getValue(String code, JsonObject lang) {

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
          e = o.get(p);
          if (!it.hasNext()) {
            if (e.isJsonPrimitive()) {
              value = e.getAsString();
            }
          }
        } else {
          break;
        }
      } else {
        break;
      }
    }

    return value;

  }

  private List<JsonObject> getLanguageMap(Locale locale) {

    if (!languageMaps.containsKey(locale)) {
      try {
        List<JsonObject> set = new ArrayList<>();
        for (String namespace : config.getLanguageNamespaces()) {
          String filename = locale.getLanguage() + File.separator + namespace + ".json";

          Resource r = getBaseDirectory().createRelative(filename);

          LOG.debug("No locale loaded, trying to load from {}", r);

          JsonParser parser = new JsonParser();
          JsonObject obj =
              (JsonObject) parser.parse(new InputStreamReader(r.getInputStream(), "UTF-8"));

          set.add(obj);
        }
        languageMaps.put(locale, set);
      } catch (JsonIOException | JsonSyntaxException | IOException e) {
        LOG.debug("Unable to load locale: {}", e.getMessage(), e);
      }
    }
    return languageMaps.get(locale);
  }


  public Resource getBaseDirectory() {

    return baseDirectory;
  }

  public void setBaseDirectory(Resource baseDirectory) {

    this.baseDirectory = baseDirectory;
  }

}
