'use strict'

angular.module('passwordResetApp').factory('ResetPasswordService', ResetPasswordService);

ResetPasswordService.$inject = ['$http'];

function ResetPasswordService($http){
	
	var service = {
		forgotPassword : forgotPassword,
		changePassword : changePassword,
	};
	return service;
	
	
	function forgotPassword(email){
		return $http.get('/iam/password-forgot/'+email);
	};
	
	function changePassword(resetKey, newPassword){
		var data = {
			resetkey : resetKey,
			password : newPassword
		}
		var config = {
			headers : {
				'Content-Type': 'application/x-www-form-urlencoded'
			},
			transformRequest: function(obj) {
		        var str = [];
		        for(var p in obj)
		        str.push(encodeURIComponent(p) + "=" + encodeURIComponent(obj[p]));
		        return str.join("&");
		    },
		}
		return $http.post('/iam/password-change', data, config);
	}
}