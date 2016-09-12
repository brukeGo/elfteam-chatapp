'use strict';

const electron = require('electron');
const ipc = electron.ipcRenderer;

/**
 * get document elements by their ids
 */

const user_in = document.getElementById('usern');
const pass_in = document.getElementById('passw');
const login_btn = document.getElementById('login-btn');
const reg_link = document.getElementById('reg-link');

/**
 * load create account window on clicking
 * on 'create account' link
 */

reg_link.addEventListener('click', (event) => {
  event.preventDefault();
  ipc.send('load-reg');
});

/**
 * login button click listener
 */

login_btn.addEventListener('click', (event) => { 
  event.preventDefault();

  if (user_in.value !== null && pass_in.value !== null &&
    user_in.value !== '' && pass_in.value !== '') {

      ipc.send('request-login', {usern: user_in.value, passw: pass_in.value});
    } else {
      ipc.send('login-err', 'username/password cannot be null');
    }
});
