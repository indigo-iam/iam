'use strict'

angular.module('dashboardApp').factory('Authorities', Authorities);

Authorities.$inject = [ '$http', '$httpParamSerializerJQLike', '$interpolate' ];

function Authorities($http, $httpParamSerializerJQLike, $interpolate) {
	var AUTH_RESOURCE = $interpolate("/iam/account/{{id}}/authorities");
	var ADMIN_ROLE_RESOURCE = $interpolate("/iam/account/{{id}}/authorities?authority=ROLE_ADMIN");
			
	var service = {
		assignAdminPrivileges : assignAdminPrivileges,
		revokeAdminPrivileges : revokeAdminPrivileges,
		getAuthorities : getAuthorities
	};

	return service;

	function resourcePath(accountId) {
		return AUTH_RESOURCE({
			id : accountId
		});
	}
	
	function adminRoleResourcePath(accountId){
		return ADMIN_ROLE_RESOURCE({
			id : accountId
		});
	}

	function assignAdminPrivileges(accountId) {
		return $http.post(adminRoleResourcePath(accountId));
	}

	function revokeAdminPrivileges(accountId) {
		
		return $http.delete(adminRoleResourcePath(accountId));
	}

	function getAuthorities(accountId) {
		
		return $http.get(resourcePath(accountId));
	}

}
