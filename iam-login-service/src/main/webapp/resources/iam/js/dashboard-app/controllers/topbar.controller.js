'use strict';

angular.module('dashboardApp').controller('TopbarController', TopbarController);

TopbarController.$inject = [ '$scope' ];

function TopbarController($scope) {

	$scope.userInfo = getUserInfo();
	console.log($scope.userInfo);

}