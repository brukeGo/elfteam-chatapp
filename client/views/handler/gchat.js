'use strict';

const electron = require('electron');
const ipc = electron.ipcRenderer;
var frd_ls = document.getElementById('frd-ls');
var send_btn = document.getElementById('send-btn');
var gname_inp = document.getElementById('gname-inp');
var members = document.getElementById('member-list');
var prog = document.getElementById('prog');
var mlist = [];

function create_li_member(frdname) {
  var li = document.createElement('li');
  var f_span = document.createElement('span');
  li.id = frdname;
  li.className = 'list-group-item';
  f_span.style['font-style'] = 'italic';
  f_span.appendChild(document.createTextNode(frdname));
  li.appendChild(f_span);
  members.style['margin-top'] = '50px';
  members.style['margin-left'] = '30px';
  members.style['margin-bottom'] = '10px';
  members.appendChild(li);
  return;
}

function append_frd_list(frds) {
  frds.forEach((frd) => {
    if (!frd.includes('(G)')) {
      var frd_btn = document.createElement('button');
      frd_btn.className += 'list-group-item list-group-item-info';
      frd_btn.appendChild(document.createTextNode(frd));
      frd_btn.addEventListener('click', (ev) => {
        ev.preventDefault();
        if (frd_btn !== undefined && frd_btn.name === 'selected') {
          frd_btn.name = 'unselected';
          frd_btn.style.background = '#bfc6c8';
          members.removeChild(frd);
          mlist.splice(mlist.indexOf(frd), 1);
        } else {
          frd_btn.name = 'selected';
          frd_btn.style.background = '#96b8c8';
          mlist.push(frd);
          create_li_member(frd);
        }
      });
      frd_ls.appendChild(frd_btn);
    }
  });
  return;
}

ipc.send('frd-ls');
ipc.on('frd-ls-success', (ev, frds) => {
  if (frds && frds.length > 0) {
    append_frd_list(frds);
  }
});

send_btn.addEventListener('click', (ev) => {
  ev.preventDefault();
  if (gname_inp.value && mlist.length > 0) {
    prog.style.display = 'block';
    ipc.send('send-create-gchat', {name: gname_inp.value, members: mlist});
  } else { 
    ipc.send('create-gchat-err', 'null group name/members');
  }
});
