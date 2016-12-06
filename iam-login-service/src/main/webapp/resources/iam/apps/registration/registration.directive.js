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
