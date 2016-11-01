'use strict';

const electron = require('electron');
const ipc = electron.ipcRenderer;
var user_in = document.getElementById('usern');

document.getElementById('reg-btn').addEventListener('click', (ev) => {
  ev.preventDefault();
  if (user_in.value !== undefined && user_in.value !== '') {
    ipc.send('request-reg', user_in.value);
  } else {
    ipc.send('login-err', 'username cannot be null');
  }
});
