'use strict';

const electron = require('electron');
const ipc = electron.ipcRenderer;

const add_btn = document.getElementById('add-btn');
const frd_username = document.getElementById('username-inp');

/**
 * add friend button click listener
 */

add_btn.addEventListener('click', (event) => { 
  event.preventDefault();

  if (frd_username.value !== null && frd_username.value !== '') {

    ipc.send('req-add-frd', {frd_usern: frd_username.value});
  } else {
    ipc.send('chat-err', 'username/password cannot be null');
  }
});
