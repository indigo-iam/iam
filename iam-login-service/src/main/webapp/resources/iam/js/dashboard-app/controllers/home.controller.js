'use strict';

angular.module('dashboardApp').controller('HomeController', HomeController);

HomeController.$inject = [ '$state', 'Utils', 'scimFactory' ];

function HomeController($state, Utils, scimFactory) {

	var home = this;

	home.userInfo = getUserInfo();
	console.log(home.userInfo);

	if (Utils.isAdmin()) {
		$state.go("user", {
			"id": home.userInfo.sub
		});	
	}
	
	scimFactory.getMe().then(function(response) {
		home.me = response.data;
		console.log(home.me);
	}, function(error) {
		$state.go("error", {
			"error": error
		});
	});

}