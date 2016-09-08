angular.module('dashboardApp').directive('box', function() {
	return {
		restrict : 'C',
		compile : function(tElement, tAttr, transclude) {
			var _this = this;
			$(tElement).find(this.boxWidgetOptions.boxWidgetSelectors.collapse)
					.click(function(e) {
						e.preventDefault();
						_this.collapse($(this));
					});
			$(tElement).find(this.boxWidgetOptions.boxWidgetSelectors.remove)
					.click(function(e) {
						e.preventDefault();
						_this.remove($(this));
					});
		},
		collapse : function(element) {
			// Find the box parent
			var box = element.parents(".box").first();
			// Find the body and the footer
			var bf = box.find(".box-body, .box-footer");
			if (!box.hasClass("collapsed-box")) {
				// Convert minus into plus
				element.children(".fa-minus").removeClass("fa-minus").addClass(
						"fa-plus");
				bf.slideUp(300, function() {
					box.addClass("collapsed-box");
				});
			} else {
				// Convert plus into minus
				element.children(".fa-plus").removeClass("fa-plus").addClass(
						"fa-minus");
				bf.slideDown(300, function() {
					box.removeClass("collapsed-box");
				});
			}
		},
		remove : function(element) {
			// Find the box parent
			var box = element.parents(".box").first();
			box.slideUp();
		},
		boxWidgetOptions : {
			boxWidgetIcons : {
				// The icon that triggers the collapse event
				collapse : 'fa fa-minus',
				// The icon that trigger the opening event
				open : 'fa fa-plus',
				// The icon that triggers the removing event
				remove : 'fa fa-times'
			},
			boxWidgetSelectors : {
				// Remove button selector
				remove : '[data-widget="remove"]',
				// Collapse button selector
				collapse : '[data-widget="collapse"]'
			}
		}

	}
});