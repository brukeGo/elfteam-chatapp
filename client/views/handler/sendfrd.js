'use strict';

const electron = require('electron');
const ipc = electron.ipcRenderer;
var username = document.getElementById('usern');
var sec = document.getElementById('sec');
var send_btn = document.getElementById('send-btn');

send_btn.addEventListener('click', (ev) => { 
  ev.preventDefault();
  if (username.value !== undefined && sec.value !== undefined && username.value !== '' && sec.value !== '') {
      ipc.send('send-frd-req', {frd_un: username.value, sec: sec.value});
      username.value = sec.value = '';
    } else {
      ipc.send('addfrd-err', 'input values cannot be null');
    }
});
