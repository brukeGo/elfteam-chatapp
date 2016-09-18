'use strict';

const electron = require('electron');
const ipc = electron.ipcRenderer;

const add_btn = document.getElementById('add-btn');
const frd_ls = document.getElementById('frd-ls');
const receiver = document.getElementById('receiver');
const msg = document.getElementById('msg-inp');
const send_btn = document.getElementById('send-btn');
const msg_ul = document.getElementById('msg-list');

/**
 * add friend button click listener
 */

add_btn.addEventListener('click', (event) => { 
  event.preventDefault();
  ipc.send('load-addfrd');
});

function append_frd_list(frd) {
  var frd_btn = document.createElement('button');
  frd_btn.className += 'list-group-item list-group-item-info';
  frd_btn.style['text-align'] = 'center';
  frd_btn.appendChild(document.createTextNode(frd));
  frd_btn.value = frd;
  frd_btn.addEventListener('click', (event) => {
    event.preventDefault();
    receiver.value = frd_btn.value;
  }); 
  frd_ls.appendChild(frd_btn);
  return;
}

ipc.send('frd-ls');
ipc.on('frd-ls-success', (ev, frds) => {
  if (frds) {
    frds.forEach((frd) => {
      append_frd_list(frd);
    });
  }
});

ipc.send('unread');
ipc.on('unread-success', (ev, unread) => {
  if (unread) {
    
  }
});

send_btn.addEventListener('click', (ev) => {
  ev.preventDefault();
  if (receiver.value !== '' && receiver.value !== null && msg.value !== '' && msg.value !== null) {
    ipc.send('send-msg', {msg: msg.value, receiver: receiver.value});
  } else {
    ipc.send('chat-err', 'Message and receiver cannot be null');
  }
});

