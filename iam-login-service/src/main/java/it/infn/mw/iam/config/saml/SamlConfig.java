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
package it.infn.mw.iam.config.saml;

import static com.google.common.collect.Sets.newHashSet;
import static it.infn.mw.iam.authn.saml.util.Saml2Attribute.EPPN;
import static it.infn.mw.iam.authn.saml.util.Saml2Attribute.EPTID;
import static it.infn.mw.iam.authn.saml.util.Saml2Attribute.EPUID;
import static java.util.concurrent.TimeUnit.HOURS;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.concurrent.TimeUnit;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.saml2.metadata.provider.FileBackedHTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataFilter;
import org.opensaml.saml2.metadata.provider.MetadataFilterChain;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.saml2.metadata.provider.ResourceBackedMetadataProvider;
import org.opensaml.util.resource.ClasspathResource;
import org.opensaml.util.resource.ResourceException;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.opensaml.xml.signature.SignatureConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.SAMLWebSSOHoKProcessingFilter;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.context.SAMLContextProviderLB;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.saml.parser.ParserPoolHolder;
import org.springframework.security.saml.processor.HTTPArtifactBinding;
import org.springframework.security.saml.processor.HTTPPAOS11Binding;
import org.springframework.security.saml.processor.HTTPPostBinding;
import org.springframework.security.saml.processor.HTTPRedirectDeflateBinding;
import org.springframework.security.saml.processor.HTTPSOAP11Binding;
import org.springframework.security.saml.processor.SAMLBinding;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.processor.SAMLProcessorImpl;
import org.springframework.security.saml.trust.httpclient.TLSProtocolConfigurer;
import org.springframework.security.saml.trust.httpclient.TLSProtocolSocketFactory;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.ArtifactResolutionProfile;
import org.springframework.security.saml.websso.ArtifactResolutionProfileImpl;
import org.springframework.security.saml.websso.SingleLogoutProfile;
import org.springframework.security.saml.websso.SingleLogoutProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.security.saml.websso.WebSSOProfileConsumerHoKImpl;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.google.common.base.Strings;

import it.infn.mw.iam.authn.AuthenticationSuccessHandlerHelper;
import it.infn.mw.iam.authn.ExternalAuthenticationFailureHandler;
import it.infn.mw.iam.authn.ExternalAuthenticationSuccessHandler;
import it.infn.mw.iam.authn.InactiveAccountAuthenticationHander;
import it.infn.mw.iam.authn.common.config.AuthenticationValidator;
import it.infn.mw.iam.authn.saml.DefaultMappingPropertiesResolver;
import it.infn.mw.iam.authn.saml.DefaultSAMLUserDetailsService;
import it.infn.mw.iam.authn.saml.IamCachingMetadataManager;
import it.infn.mw.iam.authn.saml.IamExtendedMetadataDelegate;
import it.infn.mw.iam.authn.saml.IamSamlAuthenticationProvider;
import it.infn.mw.iam.authn.saml.JustInTimeProvisioningSAMLUserDetailsService;
import it.infn.mw.iam.authn.saml.MappingPropertiesResolver;
import it.infn.mw.iam.authn.saml.SamlExceptionMessageHelper;
import it.infn.mw.iam.authn.saml.profile.DefaultSSOProfileOptionsResolver;
import it.infn.mw.iam.authn.saml.profile.IamSSOProfile;
import it.infn.mw.iam.authn.saml.profile.IamSSOProfileOptions;
import it.infn.mw.iam.authn.saml.profile.SSOProfileOptionsResolver;
import it.infn.mw.iam.authn.saml.util.FirstApplicableChainedSamlIdResolver;
import it.infn.mw.iam.authn.saml.util.IamSamlBootstrap;
import it.infn.mw.iam.authn.saml.util.IamSamlEntryPoint;
import it.infn.mw.iam.authn.saml.util.SamlIdResolvers;
import it.infn.mw.iam.authn.saml.util.SamlUserIdentifierResolver;
import it.infn.mw.iam.authn.saml.util.metadata.ResearchAndScholarshipMetadataFilter;
import it.infn.mw.iam.authn.saml.util.metadata.SirtfiAttributeMetadataFilter;
import it.infn.mw.iam.authn.util.SamlMetadataFetchTimer;
import it.infn.mw.iam.authn.util.SessionTimeoutHelper;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.JitCleanupScheduler;
import it.infn.mw.iam.config.saml.SamlConfig.ServerProperties;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;

@Configuration
@Order(value = Ordered.LOWEST_PRECEDENCE)
@Profile("saml")
@EnableConfigurationProperties({IamSamlProperties.class,
    IamSamlJITAccountProvisioningProperties.class, ServerProperties.class})
public class SamlConfig extends WebSecurityConfigurerAdapter
    implements SchedulingConfigurer, InitializingBean, DisposableBean {

  public static final Logger LOG = LoggerFactory.getLogger(SamlConfig.class);

  @Value("${iam.baseUrl}")
  private String iamBaseUrl;

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private IamTotpMfaRepository totpMfaRepository;

  @Autowired
  private ResourceLoader resourceLoader;

  @Autowired
  private SessionTimeoutHelper sessionTimeoutHelper;

  @Autowired
  private SamlUserIdentifierResolver resolver;

  @Autowired
  private MappingPropertiesResolver mappingResolver;

  @Autowired
  private AuthenticationValidator<ExpiringUsernameAuthenticationToken> validator;

  @Autowired
  private IamAccountService accountService;

  @Autowired
  private IamProperties iamProperties;

  @Autowired
  private IamSamlProperties samlProperties;

  @Autowired
  private IamSamlJITAccountProvisioningProperties jitProperties;

  @Autowired
  private InactiveAccountAuthenticationHander inactiveAccountHandler;

  @Autowired
  private AuthenticationSuccessHandlerHelper helper;

  @Autowired
  private SSOProfileOptionsResolver optionsResolver;

  @Autowired
  private IamSSOProfileOptions defaultOptions;

  @Autowired
  private HttpFirewall firewall;

  @Autowired
  private JitCleanupScheduler cleanupScheduler;

  private MultiThreadedHttpConnectionManager connectionManager;

  @ConfigurationProperties(prefix = "server")
  public static class ServerProperties {

    private String forwardHeadersStrategy;


    public String getForwardHeadersStrategy() {
      return forwardHeadersStrategy;
    }

    public void setForwardHeadersStrategy(String forwardHeadersStrategy) {
      this.forwardHeadersStrategy = forwardHeadersStrategy;
    }

    public boolean isUseForwardHeaders() {
      return "native".equals(forwardHeadersStrategy.toLowerCase())
          || "framework".equals(forwardHeadersStrategy.toLowerCase());
    }
  }

  @Configuration
  @EnableConfigurationProperties({IamSamlProperties.class,
      IamSamlJITAccountProvisioningProperties.class})
  public static class IamSamlConfig {


    protected static final String[] DEFAULT_ID_RESOLVERS =
        {EPUID.getAlias(), EPTID.getAlias(), EPPN.getAlias()};

    @Autowired
    IamSamlProperties samlProperties;

    private String[] resolverNames() {

      if (Strings.isNullOrEmpty(samlProperties.getIdResolvers())) {
        return DEFAULT_ID_RESOLVERS;
      }

      return samlProperties.getIdResolvers().split(",");
    }

    @Bean
    @Profile("saml")
    MappingPropertiesResolver mappingPropertiesResolver(
        IamSamlJITAccountProvisioningProperties jitProperties) {
      return new DefaultMappingPropertiesResolver(jitProperties.getDefaultMapping(),
          jitProperties.getEntityMapping());
    }

    @Bean
    SamlUserIdentifierResolver resolver() {

      List<SamlUserIdentifierResolver> resolvers = new ArrayList<>();

      SamlIdResolvers resolverFactory = new SamlIdResolvers();

      String[] resolverNames = resolverNames();

      for (String n : resolverNames) {
        SamlUserIdentifierResolver r = resolverFactory.byName(n);
        if (r != null) {
          resolvers.add(r);
        } else {
          LOG.warn("Unsupported saml id resolver: {}", n);
        }
      }

      if (resolvers.isEmpty()) {
        throw new IllegalStateException("Could not configure SAML id resolvers");
      }

      return new FirstApplicableChainedSamlIdResolver(resolvers);
    }

    @Bean
    @Profile("saml")
    WebSSOProfile webSSOprofile() {
      return new IamSSOProfile();
    }


    @Bean
    @Profile("saml")
    IamSSOProfileOptions defaultWebSSOProfileOptions() {

      IamSSOProfileOptions options = new IamSSOProfileOptions();
      options.setIncludeScoping(false);
      options.setNameID(samlProperties.getNameidPolicy().type());

      return options;
    }

    @Bean
    @Profile("saml")
    SSOProfileOptionsResolver optionsResolver() {
      return new DefaultSSOProfileOptionsResolver(samlProperties, defaultWebSSOProfileOptions());
    }



    @Bean
    @Profile("saml")
    static SAMLBootstrap sAMLBootstrap() {

      return new IamSamlBootstrap("RSA", SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256,
          SignatureConstants.ALGO_ID_DIGEST_SHA256);
    }

  }

  @Bean
  Timer samlMetadataFetchTimer() {
    return new SamlMetadataFetchTimer();
  }

  @Bean
  SAMLEntryPoint samlEntryPoint() {
    IamSamlEntryPoint ep = new IamSamlEntryPoint(optionsResolver);
    ep.setDefaultProfileOptions(defaultOptions);
    return ep;
  }


  @Bean
  SAMLUserDetailsService samlUserDetailsService(SamlUserIdentifierResolver resolver,
      IamAccountRepository accountRepo, InactiveAccountAuthenticationHander handler,
      MappingPropertiesResolver mpResolver) {

    if (jitProperties.getEnabled()) {

      return new JustInTimeProvisioningSAMLUserDetailsService(resolver, accountService, handler,
          accountRepo, jitProperties.getTrustedIdpsAsOptionalSet(), mpResolver);
    }

    return new DefaultSAMLUserDetailsService(resolver, accountRepo, handler);

  }

  // XML parser pool needed for OpenSAML parsing
  @Bean(initMethod = "initialize")
  StaticBasicParserPool parserPool() {

    return new StaticBasicParserPool();
  }

  @Bean(name = "parserPoolHolder")
  ParserPoolHolder parserPoolHolder() {

    return new ParserPoolHolder();
  }

  // Bindings, encoders and decoders used for creating and parsing messages
  public MultiThreadedHttpConnectionManager multiThreadedHttpConnectionManager() {

    LOG.info("Initializing SAML connection manager");
    LOG.info("SAML connection manager connection timeout: {} secs",
        samlProperties.getHttpClientConnectionTimeoutSecs());

    LOG.info("SAML connection manager socket timeout: {} secs",
        samlProperties.getHttpClientSocketTimeoutSecs());

    MultiThreadedHttpConnectionManager manager = new MultiThreadedHttpConnectionManager();

    manager.getParams()
      .setConnectionTimeout(
          (int) TimeUnit.SECONDS.toMillis(samlProperties.getHttpClientConnectionTimeoutSecs()));

    manager.getParams()
      .setSoTimeout(
          (int) TimeUnit.SECONDS.toMillis(samlProperties.getHttpClientSocketTimeoutSecs()));

    return manager;
  }

  @Bean
  HttpClient httpClient() {
    return new HttpClient(connectionManager);
  }

  @Bean
  SAMLAuthenticationProvider samlAuthenticationProvider(SamlUserIdentifierResolver resolver,
      IamAccountRepository accountRepo, InactiveAccountAuthenticationHander handler,
      MappingPropertiesResolver mpResolver,
      AuthenticationValidator<ExpiringUsernameAuthenticationToken> validator,
      SessionTimeoutHelper helper, IamTotpMfaRepository totpMfaRepository) {

    IamSamlAuthenticationProvider samlAuthenticationProvider = new IamSamlAuthenticationProvider(
        resolver, validator, helper, accountRepo, totpMfaRepository);

    samlAuthenticationProvider
      .setUserDetails(samlUserDetailsService(resolver, accountRepo, handler, mpResolver));
    samlAuthenticationProvider.setForcePrincipalAsString(false);
    return samlAuthenticationProvider;
  }


  @Bean
  SAMLContextProvider contextProvider(ServerProperties serverProperties) {

    if (serverProperties.isUseForwardHeaders()) {
      SAMLContextProviderLB cp = new SAMLContextProviderLB();

      // Assume HTTPS when sitting behind a reverse proxy
      cp.setScheme("https");

      // FIXME: find more reliable way of extracting the iamHost name
      cp.setServerName(iamProperties.getBaseUrl().substring(8));
      cp.setServerPort(443);
      cp.setIncludeServerPortInRequestURL(false);
      cp.setContextPath("/");

      return cp;
    }

    return new SAMLContextProviderImpl();
  }



  // Logger for SAML messages and events
  @Bean
  SAMLDefaultLogger samlLogger() {
    return new SAMLDefaultLogger();
  }

  private WebSSOProfileConsumerImpl setAssertionTimeChecks(WebSSOProfileConsumerImpl impl) {
    impl.setMaxAssertionTime(samlProperties.getMaxAssertionTimeSec());
    impl.setMaxAuthenticationAge(samlProperties.getMaxAuthenticationAgeSec());
    impl.setResponseSkew(300);
    return impl;
  }

  // SAML 2.0 WebSSO Assertion Consumer
  @Bean
  WebSSOProfileConsumer webSSOprofileConsumer() {

    return setAssertionTimeChecks(new WebSSOProfileConsumerImpl());
  }

  // SAML 2.0 Holder-of-Key WebSSO Assertion Consumer
  @Bean
  WebSSOProfileConsumer hokWebSSOprofileConsumer() {

    return setAssertionTimeChecks(new WebSSOProfileConsumerHoKImpl());
  }

  @Bean
  SingleLogoutProfile logoutprofile() {

    return new SingleLogoutProfileImpl();
  }

  @Bean
  KeyManager keyManager() {

    Map<String, String> passwords = new HashMap<>();
    passwords.put(samlProperties.getKeyId(), samlProperties.getKeyPassword());

    DefaultResourceLoader loader = new DefaultResourceLoader();
    Resource storeFile = loader.getResource(samlProperties.getKeystore());

    return new JKSKeyManager(storeFile, samlProperties.getKeystorePassword(), passwords,
        samlProperties.getKeyId());
  }

  //
  // Setup TLS Socket Factory
  @Bean
  TLSProtocolConfigurer tlsProtocolConfigurer() {

    return new TLSProtocolConfigurer();
  }

  @Bean
  ProtocolSocketFactory socketFactory() {

    return new TLSProtocolSocketFactory(keyManager(), null,
        samlProperties.getHostnameVerificationMode().mode());
  }

  @Bean
  Protocol socketFactoryProtocol() {

    return new Protocol("https", socketFactory(), 443);
  }

  @Bean
  ExtendedMetadata extendedMetadata() {

    final String discoveryUrl = String.format("%s/saml/discovery", iamProperties.getBaseUrl());

    ExtendedMetadata extendedMetadata = new ExtendedMetadata();
    extendedMetadata.setIdpDiscoveryEnabled(true);
    extendedMetadata.setIdpDiscoveryURL(discoveryUrl);
    extendedMetadata.setSignMetadata(false);

    return extendedMetadata;
  }

  private void configureMetadataFiltering(MetadataProvider p, IamSamlIdpMetadataProperties props) {

    List<MetadataFilter> filters = new ArrayList<>();

    if (props.getRequireRs()) {
      filters.add(new ResearchAndScholarshipMetadataFilter());
    }

    if (props.getRequireSirtfi()) {
      filters.add(new SirtfiAttributeMetadataFilter());
    }

    if (!filters.isEmpty()) {
      try {

        MetadataFilterChain chain = new MetadataFilterChain();
        chain.setFilters(filters);

        p.setMetadataFilter(chain);
      } catch (MetadataProviderException e) {
        LOG.error(e.getMessage(), e);
      }
    }
  }

  private IamExtendedMetadataDelegate metadataDelegate(MetadataProvider p,
      IamSamlIdpMetadataProperties props) {

    configureMetadataFiltering(p, props);

    IamExtendedMetadataDelegate extendedMetadataDelegate =
        new IamExtendedMetadataDelegate(p, extendedMetadata());

    extendedMetadataDelegate.setMetadataTrustCheck(true);
    extendedMetadataDelegate.setRequireValidMetadata(true);

    if (props.getKeyAlias() != null) {
      extendedMetadataDelegate.setMetadataTrustedKeys(newHashSet(props.getKeyAlias()));
    }

    extendedMetadataDelegate.setMetadataRequireSignature(props.getRequireValidSignature());

    return extendedMetadataDelegate;
  }

  private void configureLocalIamMetadata(List<MetadataProvider> providers, ParserPool parserPool)
      throws MetadataProviderException, IOException {
    if (!samlProperties.getLocalMetadata().isGenerated()) {

      if (Strings.isNullOrEmpty(samlProperties.getLocalMetadata().getLocationUrl())) {
        LOG.warn(
            "Local metadata automatic generation is disabled but metadata location URL is not set!");
      } else {

        String trimmedMetadataUrl = samlProperties.getLocalMetadata().getLocationUrl().trim();
        LOG.info("Adding local metadata provider for URL: {}", trimmedMetadataUrl);

        Resource metadataResource = resourceLoader.getResource(trimmedMetadataUrl);

        FilesystemMetadataProvider metadataProvider =
            new FilesystemMetadataProvider(metadataResource.getFile());

        metadataProvider.setParserPool(parserPool);
        ExtendedMetadata md = extendedMetadata();
        md.setLocal(true);
        ExtendedMetadataDelegate dlg = new ExtendedMetadataDelegate(metadataProvider, md);
        providers.add(dlg);
      }
    }
  }

  private List<MetadataProvider> metadataProviders(Timer metadataFetchTimer, ParserPool parserPool)
      throws MetadataProviderException, IOException, ResourceException {

    List<MetadataProvider> providers = new ArrayList<>();

    configureLocalIamMetadata(providers, parserPool);

    HttpClient httpClient = httpClient();

    for (IamSamlIdpMetadataProperties p : samlProperties.getIdpMetadata()) {

      if (Strings.isNullOrEmpty(p.getMetadataUrl())) {
        throw new IllegalStateException("Null or empty metadata url");
      }

      String trimmedMedataUrl = p.getMetadataUrl().trim();

      if (trimmedMedataUrl.startsWith("classpath:")) {
        LOG.info("Adding classpath based metadata provider for URL: {}", trimmedMedataUrl);

        ClasspathResource cpMetadataResources =
            new ClasspathResource(trimmedMedataUrl.replaceFirst("classpath:", ""));

        ResourceBackedMetadataProvider metadataProvider =
            new ResourceBackedMetadataProvider(metadataFetchTimer, cpMetadataResources);

        metadataProvider.setMinRefreshDelay((int) TimeUnit.HOURS.toMillis(12) - 1);
        metadataProvider.setMaxRefreshDelay(TimeUnit.HOURS.toMillis(12));

        metadataProvider.setParserPool(parserPool);
        providers.add(metadataDelegate(metadataProvider, p));

      } else if (trimmedMedataUrl.startsWith("file:")) {

        LOG.info("Adding File based metadata provider for URL: {}", trimmedMedataUrl);
        Resource metadataResource = resourceLoader.getResource(trimmedMedataUrl);


        FilesystemMetadataProvider metadataProvider =
            new FilesystemMetadataProvider(metadataResource.getFile());

        metadataProvider.setParserPool(parserPool);
        providers.add(metadataDelegate(metadataProvider, p));

      } else if (trimmedMedataUrl.startsWith("http")) {

        LOG.info("Adding HTTP metadata provider for URL: {}", trimmedMedataUrl);

        File metadataBackupFile = Files.createTempFile("metadata", "xml").toFile();
        metadataBackupFile.deleteOnExit();

        FileBackedHTTPMetadataProvider metadataProvider = new FileBackedHTTPMetadataProvider(
            metadataFetchTimer, httpClient, trimmedMedataUrl, metadataBackupFile.getAbsolutePath());

        metadataProvider.setParserPool(parserPool);

        long mdRefreshSecs = samlProperties.getMetadataRefreshPeriodSec();

        if (mdRefreshSecs <= 0L) {
          mdRefreshSecs = HOURS.toSeconds(12);
          LOG.warn(
              "Overriding setting for saml.metadata-refresh-period-sec with default value: {} seconds",
              mdRefreshSecs);
        }

        LOG.info("Setting max metadata refresh delay for {} to {} seconds", trimmedMedataUrl,
            mdRefreshSecs);
        metadataProvider.setMinRefreshDelay((int) SECONDS.toMillis(mdRefreshSecs - 1));
        metadataProvider.setMaxRefreshDelay(SECONDS.toMillis(mdRefreshSecs));

        metadataProvider.setFailFastInitialization(true);

        providers.add(metadataDelegate(metadataProvider, p));
      } else {
        LOG.error("Skipping invalid saml.idp-metatadata value: {}", trimmedMedataUrl);
      }
    }

    if (providers.isEmpty()) {
      String message = "Empty SAML metadata providers after initialization";
      LOG.error(message);
      throw new IllegalStateException(message);
    }

    return providers;
  }


  @Bean
  @Qualifier("metadata")
  CachingMetadataManager metadata(@Qualifier("samlMetadataFetchTimer") Timer metadataFetchTimer,
      ParserPool parserPool) throws MetadataProviderException, IOException, ResourceException {

    CachingMetadataManager manager =
        new IamCachingMetadataManager(metadataProviders(metadataFetchTimer, parserPool));
    manager.setKeyManager(keyManager());
    manager.setRefreshCheckInterval(-1);
    manager.refreshMetadata();

    return manager;
  }

  @Bean
  MetadataGenerator metadataGenerator() {

    MetadataGenerator metadataGenerator = new MetadataGenerator();

    metadataGenerator.setEntityId(samlProperties.getEntityId());
    metadataGenerator.setExtendedMetadata(extendedMetadata());
    metadataGenerator.setIncludeDiscoveryExtension(false);
    metadataGenerator.setKeyManager(keyManager());

    metadataGenerator.setEntityBaseURL(iamProperties.getBaseUrl());
    metadataGenerator.setSamlEntryPoint(samlEntryPoint());
    return metadataGenerator;
  }

  @Bean
  MetadataDisplayFilter metadataDisplayFilter() {

    return new MetadataDisplayFilter();
  }


  @Bean
  AuthenticationSuccessHandler samlAuthenticationSuccessHandler() {

    return new ExternalAuthenticationSuccessHandler("/", helper);
  }


  @Bean
  AuthenticationFailureHandler authenticationFailureHandler() {
    return new ExternalAuthenticationFailureHandler(new SamlExceptionMessageHelper());
  }

  @Bean
  SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter() throws Exception {

    SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter =
        new SAMLWebSSOHoKProcessingFilter();
    samlWebSSOHoKProcessingFilter
      .setAuthenticationSuccessHandler(samlAuthenticationSuccessHandler());
    samlWebSSOHoKProcessingFilter.setAuthenticationManager(authenticationManager());
    samlWebSSOHoKProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
    return samlWebSSOHoKProcessingFilter;
  }


  @Bean
  SAMLProcessingFilter samlWebSSOProcessingFilter() throws Exception {

    SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();
    samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManager());
    samlWebSSOProcessingFilter.setAuthenticationSuccessHandler(samlAuthenticationSuccessHandler());
    samlWebSSOProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
    return samlWebSSOProcessingFilter;
  }

  @Bean
  MetadataGeneratorFilter metadataGeneratorFilter() {

    return new MetadataGeneratorFilter(metadataGenerator());
  }

  @Bean
  SimpleUrlLogoutSuccessHandler successLogoutHandler() {

    SimpleUrlLogoutSuccessHandler successLogoutHandler = new SimpleUrlLogoutSuccessHandler();
    successLogoutHandler.setDefaultTargetUrl("/");
    return successLogoutHandler;
  }


  @Bean
  SecurityContextLogoutHandler logoutHandler() {

    SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
    logoutHandler.setInvalidateHttpSession(true);
    logoutHandler.setClearAuthentication(true);
    return logoutHandler;
  }

  @Bean
  SAMLLogoutProcessingFilter samlLogoutProcessingFilter() {

    return new SAMLLogoutProcessingFilter(successLogoutHandler(), logoutHandler());
  }

  @Bean
  SAMLLogoutFilter samlLogoutFilter() {

    return new SAMLLogoutFilter(successLogoutHandler(), new LogoutHandler[] {logoutHandler()},
        new LogoutHandler[] {logoutHandler()});
  }

  private ArtifactResolutionProfile artifactResolutionProfile() {

    final ArtifactResolutionProfileImpl artifactResolutionProfile =
        new ArtifactResolutionProfileImpl(httpClient());
    artifactResolutionProfile.setProcessor(new SAMLProcessorImpl(soapBinding()));
    return artifactResolutionProfile;
  }

  @Bean
  HTTPArtifactBinding artifactBinding(ParserPool parserPool, VelocityEngine velocityEngine) {

    return new HTTPArtifactBinding(parserPool, velocityEngine, artifactResolutionProfile());
  }

  @Bean
  HTTPSOAP11Binding soapBinding() {

    return new HTTPSOAP11Binding(parserPool());
  }

  @Bean
  HTTPPostBinding httpPostBinding(VelocityEngine velocityEngine) {

    return new HTTPPostBinding(parserPool(), velocityEngine);
  }

  @Bean
  HTTPRedirectDeflateBinding httpRedirectDeflateBinding() {

    return new HTTPRedirectDeflateBinding(parserPool());
  }

  @Bean
  HTTPSOAP11Binding httpSOAP11Binding() {

    return new HTTPSOAP11Binding(parserPool());
  }

  @Bean
  HTTPPAOS11Binding httpPAOS11Binding() {

    return new HTTPPAOS11Binding(parserPool());
  }

  @Bean
  SAMLProcessor processor(VelocityEngine velocityEngine) {

    Collection<SAMLBinding> bindings = new ArrayList<>();
    bindings.add(httpRedirectDeflateBinding());
    bindings.add(httpPostBinding(velocityEngine));
    bindings.add(artifactBinding(parserPool(), velocityEngine));
    bindings.add(httpSOAP11Binding());
    bindings.add(httpPAOS11Binding());
    return new SAMLProcessorImpl(bindings);
  }

  @Bean
  VelocityEngine velocityEngine() {
    return VelocityFactory.getEngine();
  }

  @Bean
  FilterChainProxy samlFilter() throws Exception {

    List<SecurityFilterChain> chains = new ArrayList<>();
    chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/login/**"),
        samlEntryPoint()));
    chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/logout/**"),
        samlLogoutFilter()));
    chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/metadata/**"),
        metadataDisplayFilter()));
    chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSO/**"),
        samlWebSSOProcessingFilter()));
    chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSOHoK/**"),
        samlWebSSOHoKProcessingFilter()));
    chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SingleLogout/**"),
        samlLogoutProcessingFilter()));

    FilterChainProxy fcp = new FilterChainProxy(chains);
    fcp.setFirewall(firewall);

    return fcp;
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    String pattern = "/saml/**";

    http.antMatcher(pattern);

    http.csrf().ignoringAntMatchers(pattern);

    http.authorizeRequests().antMatchers(pattern).permitAll();

    http.addFilterBefore(metadataGeneratorFilter(), ChannelProcessingFilter.class)
      .addFilterAfter(samlFilter(), BasicAuthenticationFilter.class);
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.authenticationProvider(
        samlAuthenticationProvider(resolver, accountRepo, inactiveAccountHandler, mappingResolver,
            validator, sessionTimeoutHelper, totpMfaRepository));
  }

  @Override
  public void configureTasks(ScheduledTaskRegistrar taskRegistrar) {
    cleanupScheduler.scheduleCleanupTask(taskRegistrar, jitProperties, accountService, "SAML");
  }

  @Override
  public void destroy() throws Exception {
    LOG.info("Shutting down SAML connection manager");
    connectionManager.shutdown();
    LOG.info("Shutted down SAML connection manager");
  }

  @Override
  public void afterPropertiesSet() throws Exception {
    connectionManager = multiThreadedHttpConnectionManager();
  }
}
