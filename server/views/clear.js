'use strict';

var username = document.getElementByName('username');
var s_btn = document.getElementById('search-btn');

s_btn.addEventListener('click', (event) => {
	event.preventDefault();
	if (username) {
		username = '';
	}
});
