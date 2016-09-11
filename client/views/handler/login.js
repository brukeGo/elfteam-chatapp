'use strict';

const electron = require('electron');
const ipc = electron.ipcRenderer;
const dialog = electron.remote.dialog;

/**
 * get document elements by their ids
 */

const user_in = document.getElementById('usern');
const pass_in = document.getElementById('passw');
const login_btn = document.getElementById('login-btn');
const reg_link = document.getElementById('reg-link');

/**
 * show error message
 */

function showerr(err) {
  dialog.showMessageBox({
    type: 'error',
    title: 'elfpm error',
    message: `\n${err}`,
    buttons: ['ok']
  });
  ipc.send('login-err');
}

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
      showerr('username/password cannot be null');
    }
});
