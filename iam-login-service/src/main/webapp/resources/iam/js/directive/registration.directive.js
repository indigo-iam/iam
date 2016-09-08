angular.module('registrationApp').directive('iamUsernameAvailableValidator', function($http, $q){
	return{
		require: 'ngModel',
		link: function($scope, element, attrs, ngModel){
			ngModel.$validators.uniqueUsername = function(username){
				if(username){
					return $http.get('/registration/username-available/'+username).then(
						function(response){
							ngModel.$setValidity('unique', response.data);
						});
				}
			};
		}
	}
});