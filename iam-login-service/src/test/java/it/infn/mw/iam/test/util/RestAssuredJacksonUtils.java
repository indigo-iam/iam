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
package it.infn.mw.iam.test.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ser.FilterProvider;
import com.fasterxml.jackson.databind.ser.impl.SimpleFilterProvider;

import io.restassured.RestAssured;
import io.restassured.config.ObjectMapperConfig;
import io.restassured.config.RestAssuredConfig;
import io.restassured.path.json.mapper.factory.Jackson2ObjectMapperFactory;


public class RestAssuredJacksonUtils {

  public static void initRestAssured() {

    RestAssured.config = RestAssuredConfig.config().objectMapperConfig(
	new ObjectMapperConfig().jackson2ObjectMapperFactory(RestAssuredJacksonUtils.getJacksonObjectMapperFactory()));
    RestAssured.config.getLogConfig().enableLoggingOfRequestAndResponseIfValidationFails();
  }

  public static Jackson2ObjectMapperFactory getJacksonObjectMapperFactory() {
    return (t, s) -> createJacksonObjectMapper();
  }

  public static ObjectMapper createJacksonObjectMapper() {

    FilterProvider filters = new SimpleFilterProvider().setFailOnUnknownId(false);

    ObjectMapper mapper = new ObjectMapper();
    mapper.setFilterProvider(filters);
    return mapper;

  }

}
