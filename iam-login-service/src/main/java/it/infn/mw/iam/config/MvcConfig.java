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
package it.infn.mw.iam.config;

import static com.google.common.base.Strings.isNullOrEmpty;

import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import org.mitre.openid.connect.web.ServerConfigInterceptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.http.CacheControl;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.ViewResolverRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.i18n.SessionLocaleResolver;
import org.springframework.web.servlet.resource.VersionResourceResolver;
import org.springframework.web.servlet.view.BeanNameViewResolver;
import org.springframework.web.servlet.view.InternalResourceViewResolver;
import org.springframework.web.servlet.view.JstlView;

import it.infn.mw.iam.core.userinfo.IamUserInfoInterceptor;
import it.infn.mw.iam.core.util.PoliteJsonMessageSource;
import it.infn.mw.iam.core.web.util.IamViewInfoInterceptor;

@Configuration
public class MvcConfig implements WebMvcConfigurer {

  public static final Logger LOG = LoggerFactory.getLogger(MvcConfig.class);

  @Autowired
  @Qualifier("mitreUserInfoInterceptor")
  IamUserInfoInterceptor userInfoInterceptor;

  @Autowired
  @Qualifier("mitreServerConfigInterceptor")
  ServerConfigInterceptor serverConfigInterceptor;

  @Autowired
  IamViewInfoInterceptor iamViewInfoInterceptor;

  @Autowired
  IamProperties iamProperties;

  @Value("${iam.version}")
  String iamVersion;

  @Value("${git.commit.id.abbrev}")
  String gitCommit;

  @Autowired
  Environment env;

  @Override
  public void addInterceptors(final InterceptorRegistry registry) {

    registry.addInterceptor(userInfoInterceptor);
    registry.addInterceptor(serverConfigInterceptor);
    registry.addInterceptor(iamViewInfoInterceptor);

  }

  @Override
  public void addResourceHandlers(final ResourceHandlerRegistry registry) {
    
    if (Stream.of(env.getActiveProfiles()).anyMatch(p -> p.equals("h2-test"))) {
      registry.addResourceHandler("/resources/**")
        .addResourceLocations("/resources/")
        .setCacheControl(CacheControl.noCache());
    } else {
      registry.addResourceHandler("/resources/**")
      .addResourceLocations("/resources/")
      .setCacheControl(CacheControl.maxAge(30, TimeUnit.DAYS))
      .resourceChain(false)
      .addResolver(
            new VersionResourceResolver().addFixedVersionStrategy(gitCommit, "/**"));
    }

    if (iamProperties.getLocalResources().isEnable()) {
      if (isNullOrEmpty(iamProperties.getLocalResources().getLocation())) {
        LOG.warn("Local resource serving enabled but path is null or empty!");
      } else {
       
        LOG.info("Serving local resources from {}", iamProperties.getLocalResources().getLocation());
        registry.addResourceHandler("/local-resources/**")
          .addResourceLocations(iamProperties.getLocalResources().getLocation());
      }
    }
  }

  @Override
  public void addViewControllers(final ViewControllerRegistry registry) {
    registry.addViewController("/login").setViewName("login");
  }

  @Override
  public void configureViewResolvers(final ViewResolverRegistry registry) {

    registry.viewResolver(beanNameViewResolver());
    registry.viewResolver(jspViewResolver());

  }

  private InternalResourceViewResolver jspViewResolver() {

    InternalResourceViewResolver resolver = new InternalResourceViewResolver();
    resolver.setViewClass(JstlView.class);
    resolver.setPrefix("/WEB-INF/views/");
    resolver.setSuffix(".jsp");
    resolver.setOrder(2);
    return resolver;
  }

  private BeanNameViewResolver beanNameViewResolver() {

    BeanNameViewResolver resolver = new BeanNameViewResolver();
    resolver.setOrder(1);

    return resolver;
  }

  @Bean
  public LocaleResolver localeResolver() {

    SessionLocaleResolver slr = new SessionLocaleResolver();
    slr.setDefaultLocale(Locale.US);
    return slr;
  }

  @Bean
  public MessageSource messageSource() {

    DefaultResourceLoader loader = new DefaultResourceLoader();

    PoliteJsonMessageSource messageSource = new PoliteJsonMessageSource();
    messageSource.setBaseDirectory(loader.getResource("classpath:/i18n/"));
    messageSource.setUseCodeAsDefaultMessage(true);

    return messageSource;
  }

  @Override
  public void addCorsMappings(CorsRegistry registry) {
    registry.addMapping("/iam/account/**").allowedOrigins("*");
    registry.addMapping("/iam/me/**").allowedOrigins("*");
    registry.addMapping("/scim/**").allowedOrigins("*");
  }
}
