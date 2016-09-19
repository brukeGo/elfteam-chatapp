'use strict';

const electron = require('electron');
const ipc = electron.ipcRenderer;
const dialog = electron.remote.dialog;

/**
 * get document elements by their ids
 */

const user_in = document.getElementById('usern');
const pass_in = document.getElementById('passw');
const reg_btn = document.getElementById('reg-btn');

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
  ipc.send('reg-err');
}

reg_btn.addEventListener('click', (ev) => {
  ev.preventDefault();
  // check input fields are not null or empty, then
  // send username/passw to the main process to make
  // a request to /resiter endpoint
  if (user_in.value !== null && pass_in.value !== null && 
    user_in.value !== '' && pass_in.value !== '') {
      ipc.send('request-reg', {usern: user_in.value, passw: pass_in.value});
    } else {
      showerr('username and password cannot be null');
    }
});
