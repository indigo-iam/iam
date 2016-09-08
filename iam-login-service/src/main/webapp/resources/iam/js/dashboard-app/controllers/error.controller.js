'use strict';

angular.module('dashboardApp').controller('ErrorController', ErrorController);

ErrorController.$inject = ['$scope', '$state'];

function ErrorController($scope, $state) {

	var errorCtrl = this;
	errorCtrl.name = "ErrorController";
	errorCtrl.error = $state.params.error;
}
