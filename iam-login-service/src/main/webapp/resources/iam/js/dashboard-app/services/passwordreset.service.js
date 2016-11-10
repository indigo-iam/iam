'use strict'

angular.module('dashboardApp').factory('ResetPasswordService', ResetPasswordService);

ResetPasswordService.$inject = ['$http', '$httpParamSerializerJQLike'];

function ResetPasswordService($http, $httpParamSerializerJQLike){
	
	var service = {
		forgotPassword : forgotPassword,
		changePassword : changePassword,
		updatePassword : updatePassword
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

	function updatePassword(oldPassword, newPassword){

		var config = {
			headers : {
				'Accept' : 'text/plain',
				'Content-Type': 'application/x-www-form-urlencoded'
			},
			transformRequest: function(obj) {
		        var str = [];
		        for(var p in obj)
		        str.push(encodeURIComponent(p) + "=" + encodeURIComponent(obj[p]));
		        return str.join("&");
		    }
		};

		var data = {
				'currentPassword' : oldPassword,
			'updatedPassword' : newPassword
	    };
		return $http.post('/iam/password-update', data, config);
	}
}