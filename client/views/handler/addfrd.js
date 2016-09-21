'use strict';

const electron = require('electron');
const {shell} = electron;
const ipc = electron.ipcRenderer;
var username = document.getElementById('usern');
var pubkey = document.getElementById('pubkey');
var sig = document.getElementById('sig');
var add_btn = document.getElementById('verify-btn');
var search_link = document.getElementById('search-link');

/**
 * search link click listener
 */

search_link.addEventListener('click', (ev) => {
  ev.preventDefault();
  shell.openExternal('https://localhost.daplie.com:3761');
});

/**
 * add friend button click listener
 */

add_btn.addEventListener('click', (ev) => { 
  ev.preventDefault();
  if (username.value !== null && pubkey.value !== null && sig.value !== null &&
    username.value !== '' && pubkey.value !== '' && sig.value !== '') {

      ipc.send('add-frd', {frd_usern: username.value, frd_pubkey: pubkey.value, frd_sig: sig.value});
      username.value = pubkey.value = sig.value = '';
    } else {
      ipc.send('addfrd-err', 'input values cannot be null');
    }
});
