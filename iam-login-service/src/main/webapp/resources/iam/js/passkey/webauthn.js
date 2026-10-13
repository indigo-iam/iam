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
 * Browser side of the WebAuthn ceremonies used by IAM for passkey MFA.
 *
 * The server exchanges options and credentials in the standard JSON form, with binary fields
 * base64url encoded. These helpers translate to and from the ArrayBuffers expected by
 * navigator.credentials, and run the two ceremonies against the IAM passkey endpoints.
 */
var IamWebAuthn = (function () {

  var REMOVAL_OPTIONS_URL = '/iam/passkey/removal/options';
  var REGISTRATION_OPTIONS_URL = '/iam/passkey/registration/options';
  var REGISTRATION_URL = '/iam/passkey/registration';
  var AUTHENTICATION_OPTIONS_URL = '/iam/passkey/authentication/options';

  function isSupported() {
    return typeof window !== 'undefined' && !!window.PublicKeyCredential
      && !!navigator.credentials && typeof navigator.credentials.create === 'function';
  }

  function base64UrlToBuffer(value) {
    var base64 = value.replace(/-/g, '+').replace(/_/g, '/');
    var pad = base64.length % 4;
    if (pad) {
      base64 += '===='.substring(pad);
    }
    var binary = atob(base64);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function bufferToBase64Url(buffer) {
    var bytes = new Uint8Array(buffer);
    var binary = '';
    for (var i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function decodeDescriptors(descriptors) {
    if (!descriptors) {
      return [];
    }
    return descriptors.map(function (d) {
      var result = { type: d.type, id: base64UrlToBuffer(d.id) };
      if (d.transports && d.transports.length) {
        result.transports = d.transports;
      }
      return result;
    });
  }

  function toCreationOptions(json) {
    var options = {
      rp: json.rp,
      user: {
        id: base64UrlToBuffer(json.user.id),
        name: json.user.name,
        displayName: json.user.displayName
      },
      challenge: base64UrlToBuffer(json.challenge),
      pubKeyCredParams: json.pubKeyCredParams,
      timeout: json.timeout,
      excludeCredentials: decodeDescriptors(json.excludeCredentials),
      attestation: json.attestation
    };
    if (json.authenticatorSelection) {
      options.authenticatorSelection = json.authenticatorSelection;
    }
    return options;
  }

  function toRequestOptions(json) {
    var options = {
      challenge: base64UrlToBuffer(json.challenge),
      rpId: json.rpId,
      timeout: json.timeout,
      allowCredentials: decodeDescriptors(json.allowCredentials)
    };
    if (json.userVerification) {
      options.userVerification = json.userVerification;
    }
    return options;
  }

  function serializeRegistration(credential, label) {
    var response = credential.response;
    var transports = [];
    if (typeof response.getTransports === 'function') {
      try {
        transports = response.getTransports() || [];
      } catch (e) {
        transports = [];
      }
    }
    return {
      label: label,
      id: credential.id,
      rawId: bufferToBase64Url(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: bufferToBase64Url(response.clientDataJSON),
        attestationObject: bufferToBase64Url(response.attestationObject),
        transports: transports
      }
    };
  }

  function serializeAssertion(credential) {
    var response = credential.response;
    return {
      id: credential.id,
      rawId: bufferToBase64Url(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: bufferToBase64Url(response.clientDataJSON),
        authenticatorData: bufferToBase64Url(response.authenticatorData),
        signature: bufferToBase64Url(response.signature),
        userHandle: response.userHandle ? bufferToBase64Url(response.userHandle) : null
      }
    };
  }

  function requestJson(url, body) {
    var init = {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Accept': 'application/json' }
    };
    if (body !== undefined) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    return fetch(url, init).then(function (res) {
      return res.text().then(function (text) {
        var data = null;
        if (text) {
          try {
            data = JSON.parse(text);
          } catch (e) {
            data = null;
          }
        }
        if (!res.ok) {
          var message = (data && data.error) || ('Request failed (' + res.status + ')');
          var error = new Error(message);
          error.status = res.status;
          error.data = data;
          throw error;
        }
        return data;
      });
    });
  }

  function describeError(err) {
    if (!err) {
      return 'Unknown error';
    }
    if (err.name === 'NotAllowedError' || err.name === 'AbortError') {
      return 'The passkey operation was cancelled or timed out';
    }
    if (err.name === 'InvalidStateError') {
      return 'This passkey is already registered on your account';
    }
    if (err.name === 'NotSupportedError') {
      return 'This authenticator does not support the requested passkey type';
    }
    if (err.name === 'ConstraintError') {
      return 'This authenticator cannot verify your identity (PIN or biometrics) as required';
    }
    if (err.name === 'SecurityError') {
      return 'This site is not allowed to use passkeys (check the Relying Party ID configuration)';
    }
    return err.message || String(err);
  }

  /**
   * Runs the registration ceremony and stores the new passkey on the server.
   *
   * @param label a friendly name for the passkey
   * @returns a Promise resolving to the registered passkey
   */
  function register(label) {
    if (!isSupported()) {
      return Promise.reject(new Error('Passkeys are not supported by this browser'));
    }
    return requestJson(REGISTRATION_OPTIONS_URL).then(function (options) {
      return navigator.credentials.create({ publicKey: toCreationOptions(options) });
    }).then(function (credential) {
      if (!credential) {
        throw new Error('No credential was created');
      }
      return requestJson(REGISTRATION_URL, serializeRegistration(credential, label));
    });
  }

  function assert(optionsUrl) {
    if (!isSupported()) {
      return Promise.reject(new Error('Passkeys are not supported by this browser'));
    }
    return requestJson(optionsUrl).then(function (options) {
      return navigator.credentials.get({ publicKey: toRequestOptions(options) });
    }).then(function (credential) {
      if (!credential) {
        throw new Error('No assertion was produced');
      }
      return serializeAssertion(credential);
    });
  }

  /**
   * Runs the authentication ceremony for the pre-authenticated user.
   *
   * @returns a Promise resolving to the serialized assertion, to be posted to /iam/verify
   */
  function authenticate() {
    return assert(AUTHENTICATION_OPTIONS_URL);
  }

  /**
   * Runs the ceremony that proves possession of a passkey before one is removed.
   *
   * @returns a Promise resolving to the serialized assertion, to be sent with the removal
   */
  function proveForRemoval() {
    return assert(REMOVAL_OPTIONS_URL);
  }

  return {
    isSupported: isSupported,
    base64UrlToBuffer: base64UrlToBuffer,
    bufferToBase64Url: bufferToBase64Url,
    toCreationOptions: toCreationOptions,
    toRequestOptions: toRequestOptions,
    serializeRegistration: serializeRegistration,
    serializeAssertion: serializeAssertion,
    describeError: describeError,
    register: register,
    authenticate: authenticate,
    proveForRemoval: proveForRemoval
  };
})();
