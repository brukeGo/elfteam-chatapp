'use strict';

var username = document.getElementByName('un');
var passw = document.getElementByName('pw');
var s_btn = document.getElementById('submit-btn');

s_btn.addEventListener('click', (event) => {
  event.preventDefault();
  if (username) {
    username = '';
  }
  if (passw) {
  	passw = '';
  }
});
