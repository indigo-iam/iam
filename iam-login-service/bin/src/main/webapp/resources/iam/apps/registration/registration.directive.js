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
angular.module('registrationApp').directive('iamUsernameAvailableValidator', function($http, $q){
	return{
		require: 'ngModel',
		link: function($scope, element, attrs, ngModel){
			ngModel.$validators.usernameAvailable = function(username){

				if (ngModel.$isEmpty(username)){
					return true;
				}

				if(username && ngModel.$dirty){
					return $http.get('/registration/username-available/'+username).then(
						function(response){
							ngModel.$setValidity('usernameAvailable', response.data);
						});
				}
			};
		}
	}
});

angular.module('registrationApp').directive('iamEmailAvailableValidator', function($http, $q){
	return{
		require: 'ngModel',
		link: function($scope, element, attrs, ngModel){
			ngModel.$validators.emailAvailable = function(email){

				if (ngModel.$isEmpty(email)){
					return true;
				}

				if(email && ngModel.$dirty){
					return $http.get('/registration/email-available/'+email).then(
						function(response){
							ngModel.$setValidity('emailAvailable', response.data);
						});
				}
			};
		}
	}
});
