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
