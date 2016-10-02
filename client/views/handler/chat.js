'use strict';

const electron = require('electron');
const ipc = electron.ipcRenderer;
var add_btn = document.getElementById('add-btn');
var frd_ls = document.getElementById('frd-ls');
var receiver = document.getElementById('receiver');
var msg = document.getElementById('msg-inp');
var send_btn = document.getElementById('send-btn');
var msg_ul = document.getElementById('msg-list');
var logout_btn = document.getElementById('logout-btn');
var frd_req_btn = document.getElementById('frd-req-btn');

/**
 * append a new friend to friend list
 */

function append_frd_list(frds) { 
  frds.forEach((frd) => {
    var frd_btn = document.createElement('button');
    frd_btn.className += 'list-group-item list-group-item-info';
    frd_btn.appendChild(document.createTextNode(frd.name));
    frd_btn.addEventListener('click', (ev) => {
      ev.preventDefault();
      receiver.value = frd.name;
    });
    frd_ls.appendChild(frd_btn);
  });
  return;
}

/**
 * create a li for a message to show
 */

function create_li_msg(username, msg, time, own) {
  var li = document.createElement('li');
  var lbl_div = document.createElement('div');
  var name_h = document.createElement('h5');
  var lbl_span = document.createElement('span');
  var body_div = document.createElement('div');
  var msg_div = document.createElement('div');
  var msg_p = document.createElement('p');
  var time_p = document.createElement('p');
  var time_icon = document.createElement('i');

  li.className += 'mar-btm';
  if (own) {
    lbl_div.className += 'media-left';
    body_div.className += 'media-body pad-hor';
    lbl_span.className += 'label label-info';
  } else {
    lbl_div.className += 'media-right';
    body_div.className += 'media-body pad-hor speech-right';
    lbl_span.className += 'label label-warning';
  }
  msg_div.className += 'speech';
  time_p.className += 'speech-time';
  time_icon.className += 'fa fa-clock-o';

  lbl_span.appendChild(document.createTextNode(username));
  name_h.appendChild(lbl_span);
  lbl_div.appendChild(name_h);  
  li.appendChild(lbl_div);

  msg_p.appendChild(document.createTextNode(msg));
  time_icon.appendChild(document.createTextNode(` ${time}`));
  time_p.appendChild(time_icon);

  msg_div.appendChild(msg_p);
  msg_div.appendChild(time_p);
  body_div.appendChild(msg_div);

  li.appendChild(body_div);
  msg_ul.appendChild(li);
  return;
}

ipc.send('frd-ls');
// show friend list
ipc.on('frd-ls-success', (ev, frds) => {
  if (frds) {
    append_frd_list(frds);
  }
});

add_btn.addEventListener('click', (ev) => { 
  ev.preventDefault();
  ipc.send('load-sendfrd');
});

// send button click listener
send_btn.addEventListener('click', (ev) => {
  ev.preventDefault();
  if (receiver.value !== '' && receiver.value !== null && msg.value !== '' && msg.value !== null) {
    ipc.send('send-msg', {msg: msg.value, receiver: receiver.value});
  } else {
    ipc.send('chat-err', 'Message and receiver cannot be null');
  }
});

ipc.on('send-msg-success', (ev, dat) => {
  if (dat.un && dat.msg && dat.time) {
    create_li_msg(dat.un, dat.msg, dat.time, true);
  }
});

ipc.send('fetch-unread');
ipc.on('fetch-unread-success', (ev, msgs) => {
    msgs.forEach((unread) => {
      if (unread.sen && unread.msg && unread.time) {
        create_li_msg(unread.sen, unread.msg, unread.time, false);
      }
    });
});

ipc.send('fetch-frd-req');
ipc.on('fetch-frd-req-success', () => {
  frd_req_btn.appendChild(document.createTextNode('friend request'));
  frd_req_btn.style.display = 'inline-block';
  frd_req_btn.addEventListener('click', (ev) => {
    ev.preventDefault();
    ipc.send('show-frd-req');
    if (frd_req_btn !== null) {
      frd_req_btn.style.display = 'none';
    }
  });
});

ipc.send('fetch-frd-rej');
ipc.on('check-frd-rej-success', () => {
  frd_req_btn.appendChild(document.createTextNode('friend reject'));
  frd_req_btn.style.display = 'inline-block';
  frd_req_btn.addEventListener('click', (ev) => {
    ev.preventDefault();
    ipc.send('show-frd-rej');
    if (frd_req_btn !== null) {
      frd_req_btn.style.display = 'none';
    }
  });
});

/**
 * logout click listener
 */

logout_btn.addEventListener('click', (ev) => {
  ev.preventDefault();
  ipc.send('logout');
});

