'use strict';

const electron = require('electron');
const ipc = electron.ipcRenderer;
var username = document.getElementById('usern');
var sec = document.getElementById('sec');
var veri_btn = document.getElementById('veri-btn');

/**
 * add friend button click listener
 */

veri_btn.addEventListener('click', (ev) => { 
  ev.preventDefault();
  if (username.value !== undefined && sec.value !== undefined && username.value !== '' && sec.value !== '') {
      ipc.send('verify-frd-req', {frd_un: username.value, sec: sec.value});
      username.value = sec.value = '';
    } else {
      ipc.send('getfrd-err', 'input values cannot be null');
    }
});
