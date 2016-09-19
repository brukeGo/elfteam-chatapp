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

/**
 * append a new friend to friend list
 */

function append_frd_list(frd) {
  var frd_btn = document.createElement('button');
  var badge = document.createElement('span');
  frd_btn.className += 'list-group-item list-group-item-info';
  badge.className += 'badge';
  badge.id = 'unread-count';
  frd_btn.style['text-align'] = 'center';
  frd_btn.appendChild(document.createTextNode(frd.name));
  frd_btn.value = frd.name;
  frd_btn.addEventListener('click', (ev) => {
    ev.preventDefault();
    receiver.value = frd_btn.value;
    ipc.send('show-msg', receiver.value);
  });
  if (frd.msgs.length > 0) {
    badge.appendChild(document.createTextNode(frd.msgs.length));
    frd_btn.appendChild(badge);
  }
  frd_ls.appendChild(frd_btn);
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

// get friend list
ipc.send('frd-ls');

// show friend list
ipc.on('frd-ls-success', (ev, frds) => {
  if (frds) {
    frds.forEach((frd) => {
      append_frd_list(frd);
    });
  }
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

ipc.on('send-msg-success', (ev, arg) => {
  if (arg.un && arg.msg && arg.time) {
    create_li_msg(arg.un, arg.msg, arg.time, true);
  }
});

// show unread messages
ipc.on('show-msg-success', (ev, arg) => {
  const badge_c = document.getElementById('unread-count');
  if (arg.sender && arg.msgs && arg.msgs.length > 0) {
    arg.msgs.forEach((message) => {
      create_li_msg(arg.sender, message.msg, message.time, false);
      if (badge_c !== null) {
        badge_c.style.display = 'none';
      }
    });
  }
});


