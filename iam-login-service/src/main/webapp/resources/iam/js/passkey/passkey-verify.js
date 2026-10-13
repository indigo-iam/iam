/*
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
'use strict';

/**
 * Drives the passkey form at /iam/verify: runs the assertion ceremony, then submits the
 * serialized assertion through the regular MFA verification form so that the server side
 * flow (filter, provider, success and failure handlers) is the same as for TOTP.
 */
(function () {

  function onReady(fn) {
    if (document.readyState !== 'loading') {
      fn();
    } else {
      document.addEventListener('DOMContentLoaded', fn);
    }
  }

  onReady(function () {
    var form = document.getElementById('passkey-verify-form');
    var button = document.getElementById('passkey-verify-btn');
    var input = document.getElementById('passkey-assertion');
    var error = document.getElementById('passkey-verify-error');

    if (!form || !button || !input) {
      return;
    }

    function showError(message) {
      if (error) {
        error.textContent = message;
        error.style.display = 'block';
      }
    }

    function hideError() {
      if (error) {
        error.textContent = '';
        error.style.display = 'none';
      }
    }

    if (!IamWebAuthn.isSupported()) {
      button.disabled = true;
      showError('Passkeys are not supported by this browser');
      return;
    }

    button.addEventListener('click', function (event) {
      event.preventDefault();
      hideError();
      button.disabled = true;
      IamWebAuthn.authenticate().then(function (assertion) {
        input.value = JSON.stringify(assertion);
        form.submit();
      }).catch(function (err) {
        button.disabled = false;
        showError(IamWebAuthn.describeError(err));
      });
    });
  });
})();
