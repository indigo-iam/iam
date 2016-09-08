angular.module('passwordResetApp').directive('iamPasswordCheck', function($http, $q){
	return{
		require: 'ngModel',
		scope : {
			otherModelValue : "=iamPasswordCheck"
		},
		link: function(scope, element, attrs, ngModel){
			ngModel.$validators.iamPasswordCheck = function(modelValue){
				return modelValue == scope.otherModelValue;
			};
			
			scope.$watch("otherModelValue", function(){
				ngModel.$validate();
			});
		}
	}
});