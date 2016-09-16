'use strict';

const electron = require('electron');
const {shell} = electron;
const ipc = electron.ipcRenderer;

/**
 * get document elements by their ids
 */

const username = document.getElementById('usern');
const pubkey = document.getElementById('pubkey');
const sig = document.getElementById('sig');
const add_btn = document.getElementById('verify-btn');
const search_link = document.getElementById('search-link');

/**
 * search link click listener
 */

search_link.addEventListener('click', (event) => {
  event.preventDefault();
  shell.openExternal('https://localhost.daplie.com:3019');
});

/**
 * add friend button click listener
 */

add_btn.addEventListener('click', (event) => { 
  event.preventDefault();

  if (username.value !== null && pubkey.value !== null && sig.value !== null &&
    username.value !== '' && pubkey.value !== '' && sig.value !== '') {

      ipc.send('add-frd', {frd_usern: username.value, frd_pubkey: pubkey.value, frd_sig: sig.value});
      username.value = pubkey.value = sig.value = '';
    } else {
      ipc.send('addfrd-err', 'input values cannot be null');
    }
});
/*
ipc.on('add-frd-success', () => {
  
});
*/
