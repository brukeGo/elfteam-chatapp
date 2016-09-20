'use strict';

const electron = require('electron');
const ipc = electron.ipcRenderer;
var add_btn = document.getElementById('add-btn');
var frd_ls = document.getElementById('frd-ls');
var receiver = document.getElementById('receiver');
var msg = document.getElementById('msg-inp');
var send_btn = document.getElementById('send-btn');
var msg_ul = document.getElementById('msg-list');

/**
 * append a new friend to friend list
 */

function append_frd_list(dat) {
  var frd_btn, badge;
  if (dat.frds) {
    dat.frds.forEach((frd) => {
      var count = 0;
      frd_btn = document.createElement('button');
      frd_btn.className += 'list-group-item list-group-item-info';
      frd_btn.appendChild(document.createTextNode(frd.name));
      frd_btn.value = frd.name;
      if (dat.unread) {
        dat.unread.forEach((message) => {
          if (message.sender === frd.name) {
            count += 1;
          }
        });
        badge = document.createElement('span');
        badge.className += 'badge';
        badge.id = 'unread-count';
        badge.appendChild(document.createTextNode(count));
        frd_btn.appendChild(badge);
      }
      frd_btn.addEventListener('click', (ev) => {
        ev.preventDefault();
        receiver.value = frd_btn.value;
        ipc.send('show-msg', receiver.value);
      });
      frd_ls.appendChild(frd_btn);
    });
  }
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

/**
 * add friend button click listener
 */

add_btn.addEventListener('click', (ev) => { 
  ev.preventDefault();
  ipc.send('load-addfrd');
});

ipc.send('frd-ls');

// show friend list
ipc.on('frd-ls-success', (ev, dat) => {
  append_frd_list(dat);
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
ipc.on('show-msg-success', (ev, dat) => {
  var badge = document.getElementById('unread-count');
  var btns = document.getElementsByTagName('button');
  if (dat && dat.msgs) {
    dat.msgs.forEach((unread) => {
      if (unread.msg && unread.time) {
        create_li_msg(dat.sender, unread.msg, unread.time, false);
      }
    });
    for (var i = 0; i < btns.length; i += 1) {
      if (btns[i].value === dat.sender && badge !== null) {
        btns[i].removeChild(badge);
      }
    }
  }
});

