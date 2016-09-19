'use strict';

const electron = require('electron');
const ipc = electron.ipcRenderer;

/**
 * get document elements by their ids
 */

var user_in = document.getElementById('usern');
var pass_in = document.getElementById('passw');
var reg_btn = document.getElementById('reg-btn');

reg_btn.addEventListener('click', (ev) => {
  ev.preventDefault();
  // check input fields are not null or empty, then
  // send username/passw to the main process to make
  // a request to /resiter endpoint
  if (user_in.value !== null && pass_in.value !== null && user_in.value !== '' && pass_in.value !== '') {
    ipc.send('request-reg', {usern: user_in.value, passw: pass_in.value});
  } else {
    ipc.send('reg-err', 'username and password cannot be null');
  }
});
