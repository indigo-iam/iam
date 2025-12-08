<%-- Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021 Licensed under the Apache License, Version
  2.0 (the "License" ); you may not use this file except in compliance with the License. You may obtain a copy of the
  License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  KIND, either express or implied. See the License for the specific language governing permissions and limitations under
  the License. --%>
  <%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
    <%@ taglib prefix="t" tagdir="/WEB-INF/tags/iam" %>
      <style>
        .dirty .form-control-feedback {
          display: inline-block;
        }

        .form-control-feedback {
          display: none;
        }
      </style>
      <t:page title="Activate multi factor authentication">
        <div style="text-align: center;">
          <form class="form-horizontal" id="authenticatorAppForm" name="authenticatorAppForm" method="post"
            action="/iam/authenticator-app/enable" novalidate>
            <div>
              <p>Scan the QR code through your authenticator and input a TOTP to validate configuration.</p>
              <img src="${dataUri}" />
              <p>Alternatively, enter this secret manually into your authenticator.</p>
              <p><strong>${mfaSecret}</strong></p>

              <input id="code" type="text" inputmode="numeric" placeholder="TOTP"
                autocomplete="off" spellcheck="false" name="code" autofocus>
              <br/>  
              <br/>
              <!-- Operation result message (server-provided) -->
              <c:if test="${not empty operationResultText}">
                <span id="operationResultMsg" class="help-block" style="color: #a94442;">
                  ${operationResultText}
                </span>
              </c:if>

              <input type="hidden" name="redirect" value="true" />
              <button class="btn btn-primary" type="submit" name="submit" id="submitBtn">
                Submit
              </button>
              <button class="btn btn-warning" type="button" name="reset" id="resetBtn">
                Reset
              </button>
            </div>
          </form>
          <form class="verify-form text-center" action="/logout" method="post">
            <button type="submit" class="btn btn-warning">Back to Login Page</button>
          </form>
        </div>
      </t:page>
      <script>

        document.getElementById("resetBtn").addEventListener("click", function () {
          document.getElementById("totp").value = "";
        });

      </script>