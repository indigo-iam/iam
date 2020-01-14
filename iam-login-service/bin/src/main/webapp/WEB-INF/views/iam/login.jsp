<%--

    Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2019

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

--%>
<%@ taglib prefix="authz" uri="http://www.springframework.org/security/tags"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="t" tagdir="/WEB-INF/tags/iam"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>
<t:page title="Log in">
  <jsp:attribute name="footer">
        <script type="text/javascript" src="/webjars/angularjs/angular.min.js"></script>
        <script type="text/javascript" src="/webjars/angularjs/angular-animate.js"></script>
        <script type="text/javascript" src="/webjars/angular-ui-bootstrap/ui-bootstrap-tpls.min.js"></script>
        <script type="text/javascript" src="/resources/iam/js/passwordreset.app.js"></script>
        <script type="text/javascript" src="/resources/iam/js/service/passwordreset.service.js"></script>
        <script type="text/javascript" src="/resources/iam/js/controller/passwordreset.controller.js"></script>
        <script type="text/javascript">
									angular
											.element(document)
											.ready(
													function() {
														angular
																.bootstrap(
																		document,
																		[ 'passwordResetApp' ]);
													});
								</script>
    </jsp:attribute>
  <jsp:body>
        <div id="login-error">
            <c:if test="${accessDeniedError != null}">
                <div class="alert alert-danger">Access denied: ${accessDeniedError}</div>
            </c:if>
            
            <c:if test="${ param.externalAuthenticationError != null }">
                <div class="alert alert-danger">
                    <strong>External authentication error</strong>
                    <div>${param.externalAuthenticationError}</div>
                </div>
            </c:if>

            <c:if test="${ param.error != null }">
                <div class="alert alert-danger">
                    <spring:message code="login.error" />
                </div>
            </c:if>

            <c:if test="${resetPasswordMessage != null}">
                <div class="alert alert-${resetPasswordStyle}">
                    ${resetPasswordMessage}
                </div>
            </c:if>
        </div>

        <div style="text-align: center">
            <h3>Welcome to <strong>${iamOrganisationName}</strong>
      </h3>
        </div>
        
        <form id="login-form" action="/login" method="post">
        
            <div class="signin-preamble text-muted">
              Sign in with your ${iamOrganisationName} credentials
            </div>

            <div class="form-group">
                <div class="input-group">
                    <span class="input-group-addon">
            <i class="glyphicon glyphicon-user"></i>
          </span>
                    <input id="username" class="form-control" type="text" placeholder="Username" autocomplete="off"
            spellcheck="false" value="${ login_hint }" name="username">
                </div>
            </div>

            <div class="form-group">
                <div class="input-group">
                    <span class="input-group-addon">
            <i class="glyphicon glyphicon-lock"></i>
          </span>
                    <input id="password" name="password" class="form-control" type="password" placeholder="Password">
                </div>
            </div>

            <div>
                <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}">
                <input id="login-submit" type="submit" class="btn btn-primary btn-block"
          value="${loginPageConfiguration.loginButtonText}" name="submit" class="form-control">
            </div>
        </form>

        <c:if test="${loginPageConfiguration.registrationEnabled}">
            <div id="forgot-password" ng-controller="ForgotPasswordModalController">
                <a class="btn btn-link btn-block" ng-click="open()">Forgot your password?</a>
            </div>
        </c:if>

        <div id="login-external-authn">     
            
            <c:if
        test="${loginPageConfiguration.oidcEnabled or loginPageConfiguration.samlEnabled or IAM_X509_CAN_LOGIN}">
              <div class="ext-login-preamble text-muted">
                  Or sign in with
              </div>
            </c:if>
            
            <c:if test="${IAM_X509_CAN_LOGIN}">
              <div id="x509-login" class="ext-authn-login-button">
                <a class="btn btn-block btn-default" href="/dashboard?x509ClientAuth=true"
            title="${IAM_X509_CRED.subject}">
                  Your X.509 certificate 
               </a>
              </div>
            </c:if>
            
            <c:if test="${loginPageConfiguration.oidcEnabled}">
            	<c:forEach items="${loginPageConfiguration.oidcProviders}" var="provider">
                <t:loginButton cssClass="ext-authn-login-button" href="/openid_connect_login?iss=${provider.issuer}"
            btn="${provider.loginButton}" id="oidc-login-${provider.name}" />
            	</c:forEach> 
            </c:if>

            <c:if test="${loginPageConfiguration.samlEnabled}">
                
                <!-- WAYF login button -->
                <c:if test="${iamSamlProperties.wayfLoginButton.visible}">
                  <t:loginButton href="/saml/login" btn="${iamSamlProperties.wayfLoginButton}"
            cssClass="ext-authn-login-button" id="saml-login" />
                </c:if>
                
                <!-- SAML login shortcuts -->
                <c:forEach items="${iamSamlProperties.loginShortcuts}" var="ls">
                  <c:if test="${ls.enabled}">
                    <t:loginButton cssClass="ext-authn-login-button" href="/saml/login?idp=${ls.entityId}"
                      btn="${ls.loginButton}" id="saml-login-${ls.name}" />
                  </c:if>
                </c:forEach>
            </c:if>
        </div>

        <c:if test="${loginPageConfiguration.registrationEnabled}">
            
            <div id="login-registration">
                <div class="registration-preamble text-muted">
                   Not a member?
                </div>
                <a class="btn btn-success btn-block" href="/start-registration">Register a new account</a>
            </div>
        </c:if>

        <c:if test="${loginPageConfiguration.privacyPolicyUrl.isPresent()}">
            <div id="privacy-policy">
                <a class="btn btn-link btn-block" target="_blank" rel="noopener noreferrer" href="${loginPageConfiguration.privacyPolicyUrl.get()}">
                  ${loginPageConfiguration.privacyPolicyText}
                </a>
            </div>
        </c:if>
        
        <c:if test="${not empty IAM_X509_CRED && !IAM_X509_CRED.failedVerification()}">
          <div id="x509-authn-info">
            You have been successfully authenticated as<br>
        <strong>${IAM_X509_CRED.subject}</strong>
            <c:if test="${!IAM_X509_CAN_LOGIN}">
              <p>
              This certificate is not linked to any account in this organization
              </p>
            </c:if>
          </div>
        </c:if>
    </jsp:body>
</t:page>
