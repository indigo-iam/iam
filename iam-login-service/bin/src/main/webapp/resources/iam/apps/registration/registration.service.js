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
'use strict';

angular.module('registrationApp').factory('RegistrationRequestService', RegistrationRequestService);

RegistrationRequestService.$inject = ['$http'];

function RegistrationRequestService($http){
	
	var service = {
		createRequest : createRequest,
		listRequests : listRequests,
		listPending : listPending,
		updateRequest : updateRequest
	};

	return service;

	function createRequest(request) {
		var config = {
			headers : {
				'Accept' : 'application/json',
				'Content-Type' : 'application/json'
			},
		}
		return $http.post('/registration/create', request, config);
	};

	function listRequests(status) {
		return $http.get('/registration/list', {
			params : {
				status : status
			}
		});
	};
	
	function listPending() {
		return $http.get('/registration/list/pending');
	};

	function updateRequest(uuid, decision) {
		return $http.post('/registration/' + uuid + '/' + decision);
	};
};
