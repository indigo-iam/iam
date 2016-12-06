'use strict';

angular.module('registrationApp').factory('AuthnInfo', AuthnInfo);

AuthnInfo.$inject = [ '$http' ];

function AuthnInfo($http) {

	var service = {
		getInfo : getInfo
	};

	return service;

	function getInfo() {
		return $http.get('/iam/authn-info');
	}
}