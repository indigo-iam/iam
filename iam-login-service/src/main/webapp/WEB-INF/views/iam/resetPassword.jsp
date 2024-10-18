<%--

    Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021

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
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="t" tagdir="/WEB-INF/tags/iam"%>
<t:page title="Reset password">
  <jsp:attribute name="footer">
    <script type="text/javascript" src="/webjars/angularjs/angular.min.js"></script>
    <script type="text/javascript" src="/webjars/angular-animate/angular-animate.min.js"></script>
    <script type="text/javascript" src="/webjars/angular-cookies/angular-cookies.min.js"></script>
    <script type="text/javascript" src="/webjars/angular-ui-bootstrap/dist/ui-bootstrap-tpls.js"></script>
    <script type="text/javascript" src="${resourcesPrefix}/iam/js/passwordreset.app.js"></script>
    <script type="text/javascript" src="${resourcesPrefix}/iam/js/service/passwordreset.service.js"></script>
    <script type="text/javascript" src="${resourcesPrefix}/iam/js/controller/passwordreset.controller.js"></script>
    <script type="text/javascript" src="${resourcesPrefix}/iam/js/directive/passwordreset.directive.js"></script>
    <script type="text/javascript" src="${resourcesPrefix}/iam/js/directive/password.directive.js"></script>
  </jsp:attribute>
  <jsp:body>
    <c:choose>
      <c:when test="${errorMessage != null}">
        <div id="reset-password-error">
          <div class="alert alert-danger">Error: ${errorMessage}</div>
        </div>
      </c:when>

      <c:otherwise>
        <div ng-app="passwordResetApp" ng-controller="ResetPasswordController as ctrl" ng-cloak>
          <h2 class="text-center" ng-show="ctrl.operationResult != 'ok'">
            Set your password
          </h2>
          <h2 class="text-center" ng-show="ctrl.operationResult == 'ok'">
            Your password has been reset successfully!
          </h2>

          <div ng-show="ctrl.operationResult != null">
            <div class="alert alert-danger alert-dismissable" ng-show="ctrl.operationResult == 'err'">
              {{ctrl.textAlert}}
            </div>

            <div class="row text-center" ng-show="ctrl.operationResult == 'ok'">
              <a class="btn btn-primary" href='/login'>Back to Login Page</a>
            </div>
          </div>

          <form class="reset-password-form" id="changePasswdForm" name="changePasswdForm"
            ng-submit="ctrl.submit()" ng-show="ctrl.operationResult != 'ok'" style="margin-top: 20px">

            <input type="hidden" name="resetkey" value="${resetKey}" id="resetkey"
              ng-init="ctrl.resetKey='${resetKey}'">

            <div class="form-group">
              <div
                ng-class="{'has-error': changePasswdForm.password.$dirty && changePasswdForm.password.$invalid, 'has-success': changePasswdForm.password.$dirty && !changePasswdForm.password.$invalid}">
                <input class="form-control" type="password" placeholder="Password" autocorrect="off"
                  autocapitalize="off" autocomplete="off" spellcheck="false" id="password"
                  name="password" ng-model="ctrl.password" required strong-password ng-minlength="8">
                <span class="help-block" ng-show="changePasswdForm.password.$error.strongPassword">Your password
                  must be strong and meet the following criteria:
                  <ul>
                    <li>At least 8 characters long</li>
                    <li>Include at least one uppercase letter</li>
                    <li>Include at least one lowercase letter</li>
                    <li>Include at least one number</li>
                    <li>Include at least one special character (e.g., @$!%*?&)</li>
                  </ul>
                </span>
                <span class="help-block"
                  ng-show="changePasswdForm.password.$dirty && changePasswdForm.password.$error.required">Please
                  provide a password</span>
              </div>
            </div>

            <div class="form-group">
              <div
                ng-class="{'has-error': changePasswdForm.passwordrepeat.$dirty && changePasswdForm.passwordrepeat.$invalid, 'has-success': changePasswdForm.passwordrepeat.$dirty && !changePasswdForm.passwordrepeat.$invalid}">
                <input class="form-control" type="password" placeholder="Confirm password" autocorrect="off"
                  autocapitalize="off" autocomplete="off" spellcheck="false" id="passwordrepeat"
                  name="passwordrepeat" ng-model="ctrl.passwordrepeat" required
                  iam-password-check="ctrl.password">
                <span class="help-block"
                  ng-show="changePasswdForm.passwordrepeat.$dirty && changePasswdForm.passwordrepeat.$error.required">Please
                  confirm your password</span>
                <span class="help-block"
                  ng-show="changePasswdForm.passwordrepeat.$dirty && changePasswdForm.passwordrepeat.$error.iamPasswordCheck">
                  Passwords do not match</span>
              </div>
            </div>

            <div class="form-group">
              <div>
                <input type="submit" class="btn btn-primary" value="Save" name="submit"
                  ng-disabled="changePasswdForm.$invalid">
              </div>
            </div>
          </form>
        </div>
      </c:otherwise>
    </c:choose>
  </jsp:body>
</t:page>