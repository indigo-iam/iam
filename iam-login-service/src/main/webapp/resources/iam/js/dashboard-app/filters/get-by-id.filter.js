angular.module('dashboardApp').filter('getById', function() {
	return function(input, id) {
		console.log("getById, id: ", id);
		console.log("getById, input.length: ", input.length);
		var i = 0, len = input.length;
		for (; i < len; i++) {
			console.log("Got ", input[i]);
			if (input[i].id == id) {
				console.log("Found");
				return [ i, input[i] ];
			}
		}
		return null;
	}
});