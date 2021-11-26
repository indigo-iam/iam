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

function AuthenticatorAppService($http, $httpParamSerializerJQLike){
	
	var service = {
		addMfaSecretToUser : addMfaSecretToUser,
		enableAuthenticatorApp : enableAuthenticatorApp,
		disableAuthenticatorApp : disableAuthenticatorApp
	};
	
	return service;

	function addMfaSecretToUser() {
		return $http.get('/iam/authenticator-app/add-secret');
	}
	
	// TODO two functions are broadly similar. This could be simplified into the foundations for step-up authentication
	function enableAuthenticatorApp(code){

		return $http.get('/iam/authenticator-app/enabled');
		
		// var data = $httpParamSerializerJQLike({
		// 		code: code
		// });
		
		// var config = {
		// 	headers : {
		// 		'Accept' : 'text/plain',
		// 		'Content-Type': 'application/x-www-form-urlencoded'
		// 	},
		// 	transformRequest: function(obj) {
		//         var str = [];
		//         for(var p in obj)
		//         str.push(encodeURIComponent(p) + "=" + encodeURIComponent(obj[p]));
		//         return str.join("&");
		//     }
		// }; 
		
		// return $http.post('/iam/authenticator-app/enable', data, config);
	};
	
	function disableAuthenticatorApp(code){
		
		return $http.get('/iam/authenticator-app/disabled');

		// var data = $httpParamSerializerJQLike({
		// 		code: code
		// });
		
		// var config = {
		// 	headers : {
		// 		'Accept' : 'text/plain',
		// 		'Content-Type': 'application/x-www-form-urlencoded'
		// 	},
		// 	transformRequest: function(obj) {
		//         var str = [];
		//         for(var p in obj)
		//         str.push(encodeURIComponent(p) + "=" + encodeURIComponent(obj[p]));
		//         return str.join("&");
		//     }
		// };
		
		// return $http.post('/iam/authenticator-app/disable', data, config);	
	};
}