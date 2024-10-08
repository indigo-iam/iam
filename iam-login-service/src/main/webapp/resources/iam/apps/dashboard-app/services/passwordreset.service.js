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

angular.module('dashboardApp').factory('ResetPasswordService', ResetPasswordService);

ResetPasswordService.$inject = ['$http', '$httpParamSerializerJQLike'];

function ResetPasswordService($http, $httpParamSerializerJQLike) {

	var service = {
		forgotPassword: forgotPassword,
		changePassword: changePassword,
		updatePassword: updatePassword
	};

	return service;

	function forgotPassword(email) {

		var data = $httpParamSerializerJQLike({
			email: email
		});

		var config = {
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded'
			}
		}

		return $http.post('/iam/password-reset/token', data, config);

	};

	function changePassword(resetKey, newPassword) {
		var body = JSON.stringify({ "updatedPassword": newPassword, "token": resetKey, });

		var config = {
			headers: {
				'Accept': 'application/json',
				'Content-Type': 'application/json'
			}
		}

		return $http.post('/iam/password-reset', body, config);
	}

	function updatePassword(oldPassword, newPassword) {

		var config = {
			headers: {
				'Accept': 'text/plain',
				'Content-Type': 'application/x-www-form-urlencoded'
			},
			transformRequest: function (obj) {
				var str = [];
				for (var p in obj)
					str.push(encodeURIComponent(p) + "=" + encodeURIComponent(obj[p]));
				return str.join("&");
			}
		};

		var data = {
			'currentPassword': oldPassword,
			'updatedPassword': newPassword
		};
		return $http.post('/iam/password-update', data, config);
	}
}