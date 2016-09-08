'use strict';

angular.module('dashboardApp').controller('NavController', NavController);

NavController.$inject = [ '$scope', 'Utils', 'scimFactory' ];

function NavController($scope, Utils, scimFactory) {

	var navCtrl = this;

	navCtrl.isAdmin = Utils.isAdmin();
	navCtrl.organisation = getUserInfo().organisation_name;
	
	scimFactory.getMe().then(function(response) {
		navCtrl.me = response.data;
		console.log(navCtrl.me);
	}, function(error) {
		$state.go("error", {
			"error": error
		});
	});

	if (navCtrl.isAdmin) {
		
		navCtrl.data = {};
		navCtrl.data.totUsers = 0;
		navCtrl.data.totGroups = 0;
		
		scimFactory.getUsers(1, 1).then(function(response) {
			console.log(response.data);
			navCtrl.data.totUsers = response.data.totalResults;
		}, function(error) {
			console.error(error);
			navCtrl.data.totUsers = "?";
		});
		
		scimFactory.getGroups(1, 1).then(function(response) {
			console.log(response.data);
			navCtrl.data.totGroups = response.data.totalResults;
		}, function(error) {
			console.error(error);
			navCtrl.data.totGroups = "?";
		});
		
		navCtrl.data.totRequests = "?";
	}

}