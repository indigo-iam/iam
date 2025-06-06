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
'use strict'

angular.module('dashboardApp').factory('AuthenticatorAppService', AuthenticatorAppService);

AuthenticatorAppService.$inject = ['$http', '$httpParamSerializerJQLike'];

function AuthenticatorAppService($http, $httpParamSerializerJQLike) {

	var service = {
		addMfaSecretToUser: addMfaSecretToUser,
		enableAuthenticatorApp: enableAuthenticatorApp,
		disableAuthenticatorApp: disableAuthenticatorApp,
		disableAuthenticatorAppForUser: disableAuthenticatorAppForUser,
		getMfaSettings: getMfaSettings,
		getMfaSettingsForAccount: getMfaSettingsForAccount
	};

	return service;

	function addMfaSecretToUser() {
		return $http.put('/iam/authenticator-app/add-secret');
	}

	function enableAuthenticatorApp(code) {

		var data = $httpParamSerializerJQLike({
			code: code
		});

		var config = {
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded'
			}
		};

		return $http.post('/iam/authenticator-app/enable', data, config);
	};

	function disableAuthenticatorApp(code) {

		var data = $httpParamSerializerJQLike({
			code: code
		});

		var config = {
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded'
			}
		};

		return $http.post('/iam/authenticator-app/disable', data, config);
	};

	function disableAuthenticatorAppForUser(userId) {
		return $http.delete('/iam/authenticator-app/reset/' + userId);
	}

	function handleSuccess(res) {
		return res.data.authenticatorAppActive;
	}

	function handleError(res) {
		return $q.reject(res);
	}

	function getMfaSettingsForAccount(userId) {
		return $http.get('/iam/multi-factor-settings/' + userId).then(handleSuccess).catch(handleError);
	}

	function getMfaSettings() {
		return $http.get('/iam/multi-factor-settings/').then(handleSuccess).catch(handleError);
	}
}