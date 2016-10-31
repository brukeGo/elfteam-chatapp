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
var choose_btn = document.getElementById('choose-btn');
var prog = document.getElementById('prog');
var scrol = document.getElementById('chat-scrol');

function append_frd_list(frds) { 
  frds.forEach((frd) => {
    var frd_btn = document.createElement('button');
    frd_btn.className += 'list-group-item list-group-item-info';
    frd_btn.appendChild(document.createTextNode(frd.name));
    frd_btn.addEventListener('click', (ev) => {
      ev.preventDefault();
      if (frd_btn !== undefined && frd_btn.name === 'selected') {
        frd_btn.name = 'unselected';
        frd_btn.style.background = '#bfc6c8';
        receiver.value = '';
      } else {
        frd_btn.name = 'selected';
        frd_btn.style.background = '#96b8c8';
        receiver.value = frd.name;
      }
    });
    frd_ls.appendChild(frd_btn);
  });
  return;
}

function create_li_msg(dat, own) {
  var li = document.createElement('li');
  var lbl_div = document.createElement('div');
  var name_h = document.createElement('h5');
  var lbl_span = document.createElement('span');
  var body_div = document.createElement('div');
  var msg_div = document.createElement('div');
  var msg_p = document.createElement('p');
  var time_p = document.createElement('p');
  var time_icon = document.createElement('span');

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
  time_icon.className += 'glyphicon glyphicon-time';

  lbl_span.appendChild(document.createTextNode(dat.sen));
  name_h.appendChild(lbl_span);
  lbl_div.appendChild(name_h);  
  li.appendChild(lbl_div);
  msg_p.appendChild(document.createTextNode(dat.msg));
  msg_div.appendChild(msg_p);

  if (dat.files && dat.files !== 0) {  
    dat.files.forEach((f) => {
      var file_icon = document.createElement('span');
      var file_link = document.createElement('a');
      file_link.id = f;
      file_link.className += 'file-link';
      file_icon.className += 'glyphicon glyphicon-paperclip';
      file_link.appendChild(file_icon);
      file_link.appendChild(document.createTextNode(` ${f} `));
      if (!own) {
        file_link.addEventListener('click', (ev) => {
          ev.preventDefault();
          ipc.send('save-file', f);
        });
      }
      msg_div.appendChild(file_link);
    });
  }
  time_p.appendChild(time_icon);
  time_p.appendChild(document.createTextNode(` ${dat.time} `));
  time_p.appendChild(document.createTextNode(` \u2714`));
  msg_div.appendChild(time_p);
  body_div.appendChild(msg_div);
  li.appendChild(body_div);
  msg_ul.appendChild(li);
  scrol.scrollTop = scrol.scrollHeight;
  return;
}

function create_li_path(file) {
  var li = document.createElement('li');
  var f_span = document.createElement('span');
  li.id = file;
  li.className = 'list-group-item';
  f_span.style['font-style'] = 'italic';
  f_span.appendChild(document.createTextNode(file));
  li.appendChild(f_span);
  msg_ul.style['margin-top'] = '10px';
  msg_ul.style['margin-bottom'] = '10px';
  msg_ul.appendChild(li);
  return;
}

ipc.send('fetch-frd-req');
ipc.send('fetch-frd-rej');

ipc.send('frd-ls');
ipc.on('frd-ls-success', (ev, frds) => {
  if (frds) {
    append_frd_list(frds);
  }
});

add_btn.addEventListener('click', (ev) => { 
  ev.preventDefault();
  ipc.send('load-sendfrd');
});

send_btn.addEventListener('click', (ev) => {
  ev.preventDefault();
  if (receiver.value !== undefined && msg.value !== undefined && receiver.value !== '' && msg.value !== '') {
    ipc.send('send-msg', {msg: msg.value, receiver: receiver.value});
  } else { 
    ipc.send('main-err', 'null message/receiver. Click on one of your friends to assign a receiver');
  }
});

ipc.on('show-prog', () => {
  prog.style.display = 'block';
});

ipc.on('send-msg-success', (ev, dat) => {
  if (prog) {
    prog.style.display = 'none';
  }
  if (dat) {
    create_li_msg(dat, true);
  }
});

ipc.send('fetch-unread');
ipc.on('fetch-unread-success', (ev, msgs) => {
  msgs.forEach((unread) => {
    create_li_msg(unread, false);
  });
});

choose_btn.addEventListener('click', (ev) => { 
  ev.preventDefault();
  ipc.send('open-choose');
});

ipc.on('open-choose-success', (ev, paths) => {
  paths.forEach((f) => {
    create_li_path(f);
  });
});

ipc.on('save-file-success', (ev, fname) => {
  var file_li = document.getElementById(fname);
  if (file_li !== undefined) {
    file_li.parentNode.removeChild(file_li);
  }
});

logout_btn.addEventListener('click', (ev) => {
  ev.preventDefault();
  ipc.send('logout');
});
