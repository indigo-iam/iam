package it.infn.mw.iam.config.saml;

import static it.infn.mw.iam.authn.saml.util.SamlIdResolvers.eppn;
import static it.infn.mw.iam.authn.saml.util.SamlIdResolvers.epuid;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
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
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.SAMLDiscovery;
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
import org.springframework.security.saml.websso.WebSSOProfileECPImpl;
import org.springframework.security.saml.websso.WebSSOProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import it.infn.mw.iam.authn.ExternalAuthenticationFailureHandler;
import it.infn.mw.iam.authn.TimestamperSuccessHandler;
import it.infn.mw.iam.authn.saml.SAMLUserDetailsServiceImpl;
import it.infn.mw.iam.authn.saml.IamSamlAuthenticationProvider;
import it.infn.mw.iam.authn.saml.SamlExceptionMessageHelper;
import it.infn.mw.iam.authn.saml.util.FirstApplicableChainedSamlIdResolver;
import it.infn.mw.iam.authn.saml.util.SamlUserIdentifierResolver;
import it.infn.mw.iam.config.saml.SamlConfig.IamProperties;
import it.infn.mw.iam.config.saml.SamlConfig.ServerProperties;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@Configuration
@Order(value = Ordered.LOWEST_PRECEDENCE)
@Profile("saml")
@EnableConfigurationProperties({IamSamlProperties.class, IamProperties.class,
    ServerProperties.class})
public class SamlConfig extends WebSecurityConfigurerAdapter {

  @Autowired
  ResourceLoader resourceLoader;

  @Autowired
  SamlUserIdentifierResolver resolver;

  @Autowired
  IamAccountRepository repo;

  @Autowired
  IamProperties iamProperties;

  @Autowired
  IamSamlProperties samlProperties;

  @Autowired
  ServerProperties serverProperties;

  @ConfigurationProperties(prefix = "iam")
  public static class IamProperties {

    private String baseUrl;

    public String getBaseUrl() {
      return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
      this.baseUrl = baseUrl;
    }
  }

  @ConfigurationProperties(prefix = "server")
  public static class ServerProperties {

    private boolean useForwardHeaders;

    public boolean isUseForwardHeaders() {
      return useForwardHeaders;
    }

    public void setUseForwardHeaders(boolean useForwardHeaders) {
      this.useForwardHeaders = useForwardHeaders;
    }
  }

  @Configuration
  public static class IamSamlConfig {

    @Bean
    public SamlUserIdentifierResolver resolver() {

      List<SamlUserIdentifierResolver> resolvers = Arrays.asList(epuid(), eppn());

      return new FirstApplicableChainedSamlIdResolver(resolvers);
    }

  }

  @Bean
  public SAMLUserDetailsService samlUserDetailsService(SamlUserIdentifierResolver resolver,
      IamAccountRepository accountRepo) {

    return new SAMLUserDetailsServiceImpl(resolver, accountRepo);

  }

  @Bean
  public VelocityEngine velocityEngine() {

    return VelocityFactory.getEngine();
  }

  // XML parser pool needed for OpenSAML parsing
  @Bean(initMethod = "initialize")
  public StaticBasicParserPool parserPool() {

    return new StaticBasicParserPool();
  }

  @Bean(name = "parserPoolHolder")
  public ParserPoolHolder parserPoolHolder() {

    return new ParserPoolHolder();
  }

  // Bindings, encoders and decoders used for creating and parsing messages
  @Bean
  public MultiThreadedHttpConnectionManager multiThreadedHttpConnectionManager() {

    return new MultiThreadedHttpConnectionManager();
  }

  @Bean
  public HttpClient httpClient() {

    return new HttpClient(multiThreadedHttpConnectionManager());
  }

  // SAML Authentication Provider responsible for validating of received SAML
  // messages
  @Bean
  public SAMLAuthenticationProvider samlAuthenticationProvider(SamlUserIdentifierResolver resolver,
      IamAccountRepository accountRepo) {

    IamSamlAuthenticationProvider samlAuthenticationProvider = new IamSamlAuthenticationProvider();
    samlAuthenticationProvider.setUserDetails(samlUserDetailsService(resolver, accountRepo));
    samlAuthenticationProvider.setForcePrincipalAsString(false);
    return samlAuthenticationProvider;
  }


  @Bean
  public SAMLContextProvider contextProvider() {

    if (serverProperties.isUseForwardHeaders()) {
      SAMLContextProviderLB cp = new SAMLContextProviderLB();

      // Assume https when sitting behind a reverse proxy
      cp.setScheme("https");

      // FIXME: find more reliable way of extracting the host name
      cp.setServerName(iamProperties.getBaseUrl().substring(8));
      cp.setServerPort(443);
      cp.setIncludeServerPortInRequestURL(false);
      cp.setContextPath("/");

      return cp;
    }

    return new SAMLContextProviderImpl();
  }

  // Initialization of OpenSAML library
  @Bean
  public static SAMLBootstrap sAMLBootstrap() {

    return new SAMLBootstrap();
  }

  // Logger for SAML messages and events
  @Bean
  public SAMLDefaultLogger samlLogger() {

    return new SAMLDefaultLogger();
  }

  // SAML 2.0 WebSSO Assertion Consumer
  @Bean
  public WebSSOProfileConsumer webSSOprofileConsumer() {

    return new WebSSOProfileConsumerImpl();
  }

  // SAML 2.0 Holder-of-Key WebSSO Assertion Consumer
  @Bean
  public WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer() {

    return new WebSSOProfileConsumerHoKImpl();
  }

  // SAML 2.0 Web SSO profile
  @Bean
  public WebSSOProfile webSSOprofile() {

    return new WebSSOProfileImpl();
  }

  // SAML 2.0 Holder-of-Key Web SSO profile
  @Bean
  public WebSSOProfileConsumerHoKImpl hokWebSSOProfile() {

    return new WebSSOProfileConsumerHoKImpl();
  }

  // SAML 2.0 ECP profile
  @Bean
  public WebSSOProfileECPImpl ecpprofile() {

    return new WebSSOProfileECPImpl();
  }

  @Bean
  public SingleLogoutProfile logoutprofile() {

    return new SingleLogoutProfileImpl();
  }

  @Bean
  public KeyManager keyManager() {

    Map<String, String> passwords = new HashMap<String, String>();
    passwords.put(samlProperties.getKeyId(), samlProperties.getKeyPassword());

    DefaultResourceLoader loader = new DefaultResourceLoader();
    Resource storeFile = loader.getResource(samlProperties.getKeystore());

    return new JKSKeyManager(storeFile, samlProperties.getKeystorePassword(), passwords,
        samlProperties.getKeyId());
  }

  //
  // Setup TLS Socket Factory
  @Bean
  public TLSProtocolConfigurer tlsProtocolConfigurer() {

    return new TLSProtocolConfigurer();
  }

  @Bean
  public ProtocolSocketFactory socketFactory() {

    return new TLSProtocolSocketFactory(keyManager(), null, "default");
  }

  @Bean
  public Protocol socketFactoryProtocol() {

    return new Protocol("https", socketFactory(), 443);
  }

  //
  // @Bean
  // public MethodInvokingFactoryBean socketFactoryInitialization() {
  //
  // MethodInvokingFactoryBean methodInvokingFactoryBean = new MethodInvokingFactoryBean();
  // methodInvokingFactoryBean.setTargetClass(Protocol.class);
  // methodInvokingFactoryBean.setTargetMethod("registerProtocol");
  // Object[] args = {"https", socketFactoryProtocol()};
  // methodInvokingFactoryBean.setArguments(args);
  // return methodInvokingFactoryBean;
  // }

  @Bean
  public WebSSOProfileOptions defaultWebSSOProfileOptions() {

    WebSSOProfileOptions webSSOProfileOptions = new WebSSOProfileOptions();
    webSSOProfileOptions.setIncludeScoping(false);

    webSSOProfileOptions.setNameID(NameIDType.PERSISTENT);

    return webSSOProfileOptions;
  }

  // Entry point to initialize authentication, default values taken from
  // properties file
  @Bean
  public SAMLEntryPoint samlEntryPoint() {

    SAMLEntryPoint samlEntryPoint = new SAMLEntryPoint();
    samlEntryPoint.setDefaultProfileOptions(defaultWebSSOProfileOptions());
    return samlEntryPoint;
  }

  // Setup advanced info about metadata
  @Bean
  public ExtendedMetadata extendedMetadata() {

    ExtendedMetadata extendedMetadata = new ExtendedMetadata();
    extendedMetadata.setIdpDiscoveryEnabled(true);
    extendedMetadata.setSignMetadata(false);
    return extendedMetadata;
  }

  // IDP Discovery Service
  @Bean
  public SAMLDiscovery samlIDPDiscovery() {

    SAMLDiscovery idpDiscovery = new SAMLDiscovery();
    idpDiscovery.setIdpSelectionPath("/saml/idpSelection");
    return idpDiscovery;
  }

  @Bean
  @Qualifier("local")
  public ExtendedMetadataDelegate localIdpMetadataProvider()
      throws MetadataProviderException, URISyntaxException, IOException {

    Resource metadataResource = resourceLoader.getResource(samlProperties.getIdpMetadata());

    FilesystemMetadataProvider localIdpMetadataProvider =
        new FilesystemMetadataProvider(metadataResource.getFile());

    localIdpMetadataProvider.setParserPool(new BasicParserPool());
    localIdpMetadataProvider.initialize();

    ExtendedMetadataDelegate extendedMetadataDelegate =
        new ExtendedMetadataDelegate(localIdpMetadataProvider, extendedMetadata());
    extendedMetadataDelegate.setMetadataTrustCheck(true);
    extendedMetadataDelegate.setMetadataRequireSignature(false);
    return extendedMetadataDelegate;

  }

  // IDP Metadata configuration - paths to metadata of IDPs in circle of trust
  // is here
  @Bean
  @Qualifier("metadata")
  public CachingMetadataManager metadata()
      throws MetadataProviderException, URISyntaxException, IOException {

    List<MetadataProvider> providers = new ArrayList<MetadataProvider>();
    // providers.add(ssoCircleExtendedMetadataProvider());
    providers.add(localIdpMetadataProvider());
    return new CachingMetadataManager(providers);
  }

  // Filter automatically generates default SP metadata
  @Bean
  public MetadataGenerator metadataGenerator() {

    MetadataGenerator metadataGenerator = new MetadataGenerator();

    metadataGenerator.setEntityId(samlProperties.getEntityId());
    metadataGenerator.setExtendedMetadata(extendedMetadata());
    metadataGenerator.setIncludeDiscoveryExtension(false);
    metadataGenerator.setKeyManager(keyManager());

    if (serverProperties.isUseForwardHeaders()) {
      metadataGenerator.setEntityBaseURL(iamProperties.getBaseUrl());
    }

    return metadataGenerator;
  }

  @Bean
  public MetadataDisplayFilter metadataDisplayFilter() {

    return new MetadataDisplayFilter();
  }


  @Bean
  public AuthenticationSuccessHandler successRedirectHandler() {

    SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler =
        new SavedRequestAwareAuthenticationSuccessHandler();
    successRedirectHandler.setDefaultTargetUrl("/");

    return new TimestamperSuccessHandler(successRedirectHandler);
  }


  @Bean
  public AuthenticationFailureHandler authenticationFailureHandler() {
    return new ExternalAuthenticationFailureHandler(new SamlExceptionMessageHelper());
  }

  @Bean
  public SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter() throws Exception {

    SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter =
        new SAMLWebSSOHoKProcessingFilter();
    samlWebSSOHoKProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler());
    samlWebSSOHoKProcessingFilter.setAuthenticationManager(authenticationManager());
    samlWebSSOHoKProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
    return samlWebSSOHoKProcessingFilter;
  }


  @Bean
  public SAMLProcessingFilter samlWebSSOProcessingFilter() throws Exception {

    SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();
    samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManager());
    samlWebSSOProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler());
    samlWebSSOProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
    return samlWebSSOProcessingFilter;
  }

  @Bean
  public MetadataGeneratorFilter metadataGeneratorFilter() {

    return new MetadataGeneratorFilter(metadataGenerator());
  }

  @Bean
  public SimpleUrlLogoutSuccessHandler successLogoutHandler() {

    SimpleUrlLogoutSuccessHandler successLogoutHandler = new SimpleUrlLogoutSuccessHandler();
    successLogoutHandler.setDefaultTargetUrl("/");
    return successLogoutHandler;
  }


  @Bean
  public SecurityContextLogoutHandler logoutHandler() {

    SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
    logoutHandler.setInvalidateHttpSession(true);
    logoutHandler.setClearAuthentication(true);
    return logoutHandler;
  }

  @Bean
  public SAMLLogoutProcessingFilter samlLogoutProcessingFilter() {

    return new SAMLLogoutProcessingFilter(successLogoutHandler(), logoutHandler());
  }

  @Bean
  public SAMLLogoutFilter samlLogoutFilter() {

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
  public HTTPArtifactBinding artifactBinding(ParserPool parserPool, VelocityEngine velocityEngine) {

    return new HTTPArtifactBinding(parserPool, velocityEngine, artifactResolutionProfile());
  }

  @Bean
  public HTTPSOAP11Binding soapBinding() {

    return new HTTPSOAP11Binding(parserPool());
  }

  @Bean
  public HTTPPostBinding httpPostBinding() {

    return new HTTPPostBinding(parserPool(), velocityEngine());
  }

  @Bean
  public HTTPRedirectDeflateBinding httpRedirectDeflateBinding() {

    return new HTTPRedirectDeflateBinding(parserPool());
  }

  @Bean
  public HTTPSOAP11Binding httpSOAP11Binding() {

    return new HTTPSOAP11Binding(parserPool());
  }

  @Bean
  public HTTPPAOS11Binding httpPAOS11Binding() {

    return new HTTPPAOS11Binding(parserPool());
  }

  @Bean
  public SAMLProcessor processor() {

    Collection<SAMLBinding> bindings = new ArrayList<SAMLBinding>();
    bindings.add(httpRedirectDeflateBinding());
    bindings.add(httpPostBinding());
    bindings.add(artifactBinding(parserPool(), velocityEngine()));
    bindings.add(httpSOAP11Binding());
    bindings.add(httpPAOS11Binding());
    return new SAMLProcessorImpl(bindings);
  }

  /**
   * Define the security filter chain in order to support SSO Auth by using SAML 2.0
   * 
   * @return Filter chain proxy @throws Exception
   */
  @Bean
  public FilterChainProxy samlFilter() throws Exception {

    List<SecurityFilterChain> chains = new ArrayList<SecurityFilterChain>();
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
    chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/discovery/**"),
        samlIDPDiscovery()));
    return new FilterChainProxy(chains);
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {

    http.antMatcher("/saml/**");

    http.csrf().ignoringAntMatchers("/saml/**");

    http.authorizeRequests().antMatchers("/saml/**").permitAll();

    http.addFilterBefore(metadataGeneratorFilter(), ChannelProcessingFilter.class)
      .addFilterAfter(samlFilter(), BasicAuthenticationFilter.class);
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {

    auth.authenticationProvider(samlAuthenticationProvider(resolver, repo));
  }
}
