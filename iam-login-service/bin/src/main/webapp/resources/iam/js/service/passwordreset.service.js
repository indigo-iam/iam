/*
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2019
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

angular.module('passwordResetApp').factory('ResetPasswordService', ResetPasswordService);

ResetPasswordService.$inject = ['$http', '$httpParamSerializerJQLike'];

function ResetPasswordService($http, $httpParamSerializerJQLike){
	
	var service = {
		forgotPassword : forgotPassword,
		changePassword : changePassword,
	};
	
	return service;
	
	function forgotPassword(email){
		
		var data = $httpParamSerializerJQLike({
				email: email
		});
		
		var config = {
			headers : {
				'Content-Type' : 'application/x-www-form-urlencoded'
			}
		} 
		
		return $http.post('/iam/password-reset/token', data, config);
		
	};
	
	function changePassword(resetKey, newPassword){
		var data = $httpParamSerializerJQLike({
			token : resetKey,
			password : newPassword
		});
		
		var config = {
			headers : {
				'Content-Type': 'application/x-www-form-urlencoded'
			}
		}
		
		return $http.post('/iam/password-reset', data, config);
	}
}