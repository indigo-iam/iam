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
          angular.element(document).ready(function() {
            angular.bootstrap(document, [ 'passwordResetApp' ]);
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

    <form id="login-form" action="/login" method="post">

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
        <input type="submit" class="btn btn-primary btn-block" value="Login" name="submit" class="form-control">
      </div>
    </form>

    <div id="login-external-authn">
      <c:if test="${loginPageConfiguration.googleEnabled}">
        <div id="google-login" class="ext-authn-login-button">
          <a class='btn btn-block btn-social btn-google' href="/openid_connect_login">
          <i  class="fa fa-google"></i> Sign in with Google</a>
        </div>
      </c:if>

      <c:if test="${loginPageConfiguration.samlEnabled}">
        <div id="saml-login" class="ext-authn-login-button">
          <a class="btn btn-block btn-default" href="/saml/login"> Sign in with SAML</a>
        </div>
      </c:if>
    </div>
        
    <c:if test="${loginPageConfiguration.registrationEnabled}">
      <div id="login-registration">
        <a class="btn btn-success btn-block" href="/register">Register a new account</a>
      </div>
      <div id="forgot-password" ng-controller="ForgotPasswordModalController">
        <a class="btn btn-link btn-block" ng-click="open()">Forgot your password?</a>
      </div>
    </c:if>
  </jsp:body>
</t:page>
  
