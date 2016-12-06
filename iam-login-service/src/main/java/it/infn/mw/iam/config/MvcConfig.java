package it.infn.mw.iam.config;

import java.util.Locale;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.web.servlet.AsyncHandlerInterceptor;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.ViewResolverRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.springframework.web.servlet.i18n.SessionLocaleResolver;
import org.springframework.web.servlet.view.BeanNameViewResolver;
import org.springframework.web.servlet.view.InternalResourceViewResolver;
import org.springframework.web.servlet.view.JstlView;

import it.infn.mw.iam.core.util.PoliteJsonMessageSource;

@Configuration
public class MvcConfig extends WebMvcConfigurerAdapter {

  @Autowired
  @Qualifier("mitreUserInfoInterceptor")
  AsyncHandlerInterceptor userInfoInterceptor;

  @Autowired
  @Qualifier("mitreServerConfigInterceptor")
  AsyncHandlerInterceptor serverConfigInterceptor;

  @Autowired
  AsyncHandlerInterceptor iamViewInfoInterceptor;

  @Override
  public void addInterceptors(final InterceptorRegistry registry) {

    registry.addInterceptor(userInfoInterceptor);
    registry.addInterceptor(serverConfigInterceptor);
    registry.addInterceptor(iamViewInfoInterceptor);

  }

  @Override
  public void addResourceHandlers(final ResourceHandlerRegistry registry) {

    registry.addResourceHandler("/resources/**").addResourceLocations("/resources/");

  }

  @Override
  public void addViewControllers(final ViewControllerRegistry registry) {

    registry.addViewController("/login").setViewName("login");
    registry.addViewController("/error").setViewName("error");
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
