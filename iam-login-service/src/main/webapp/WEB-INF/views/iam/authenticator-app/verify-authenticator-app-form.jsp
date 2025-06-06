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
<html>
<div>
  <form class="verify-form" action="/iam/verify" method="post">
    <div class="verify-preamble text-muted">
      For your security, please enter a TOTP from your authenticator
    </div>
    <div class="form-group">
      <div class="input-group">
        <span class="input-group-addon">
          <i class="glyphicon glyphicon-lock"></i>
        </span>
        <input id="totp" class="form-control" type="text" inputmode="numeric" placeholder="TOTP" autocomplete="off"
          spellcheck="false" name="totp" autofocus>
      </div>
    </div>
    <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}">
    <input id="verify-submit" type="submit" class="btn btn-primary btn-block"
      value="${multiFactorVerificationPageConfiguration.verifyButtonText}" name="submit" class="form-control">
</form>
<form class="verify-form text-center" action="/logout" method="post">
  <button type="submit" class="btn btn-warning">Back to Login Page</button>
</form>
</div>

</html>