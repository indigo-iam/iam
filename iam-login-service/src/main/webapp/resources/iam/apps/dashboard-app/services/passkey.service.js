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

angular.module('dashboardApp').factory('PasskeyService', PasskeyService);

PasskeyService.$inject = ['$http', '$q'];

function PasskeyService($http, $q) {

	var service = {
		isSupported: isSupported,
		getPasskeys: getPasskeys,
		registerPasskey: registerPasskey,
		removePasskeyWithPasskey: removePasskeyWithPasskey,
		removePasskeyWithTotp: removePasskeyWithTotp,
		removePasskey: removePasskey,
		resetPasskeysForUser: resetPasskeysForUser,
		describeError: describeError
	};

	return service;

	function isSupported() {
		return typeof IamWebAuthn !== 'undefined' && IamWebAuthn.isSupported();
	}

	function getPasskeys() {
		return $http.get('/iam/passkey');
	}

	function registerPasskey(label) {
		return $q.when(IamWebAuthn.register(label));
	}

	// Removing a passkey requires a proof of a second factor: an assertion made with any of the
	// registered passkeys, or a code of the authenticator app when it is active
	function removePasskeyWithPasskey(passkeyId) {
		return $q.when(IamWebAuthn.proveForRemoval()).then(function(assertion) {
			return removePasskey(passkeyId, { assertion: assertion });
		});
	}

	function removePasskeyWithTotp(passkeyId, totp) {
		return removePasskey(passkeyId, { totp: totp });
	}

	// Without a proof the server only accepts the removal while passkeys are disabled
	function removePasskey(passkeyId, proof) {
		return $http({
			method: 'DELETE',
			url: '/iam/passkey/' + passkeyId,
			data: proof || {},
			headers: { 'Content-Type': 'application/json' }
		});
	}

	function resetPasskeysForUser(userId) {
		return $http.delete('/iam/passkey/reset/' + userId);
	}

	function describeError(error) {
		if (error && error.data && error.data.error) {
			return error.data.error;
		}
		// An $http rejection carries a numeric status (0 when the request never reached the server)
		if (error && typeof error.status === 'number') {
			return error.status ? 'Request failed (' + error.status + ')' : 'The server cannot be reached';
		}
		return IamWebAuthn.describeError(error);
	}
}
