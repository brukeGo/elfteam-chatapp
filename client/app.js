'use strict';

/**
 * app dependencies and consts
 */

const path = require('path');
const electron = require('electron');
const {app, BrowserWindow, dialog, ipcMain} = electron;
const iconpath = path.join(__dirname, 'resources', 'icon.png');
const auth = require('./auth.js');

/**
 * view files paths
 */

const login_index = `file://${__dirname}/views/login.html`;
const chat_index = `file://${__dirname}/views/chat.html`;
const getfrd_index = `file://${__dirname}/views/get_frd_req.html`;
const sendfrd_index = `file://${__dirname}/views/send_frd_req.html`;

/**
 * keep the reference to the main window.
 * otherwise, it will be dereferenced by the
 * javascript garbage collector.
 */

var login_win = null;
var chat_win = null;
var sendfrd_win = null;
var getfrd_win = null;

var frd_req_timer;
var frd_rej_timer;
var unread_timer;

/**
 * show error message
 */

function showerr(err) {
  dialog.showMessageBox({
    type: 'error',
    title: 'elfocrypt error',
    message: `\n${err}`,
    buttons: ['ok']
  });
}

/**
 * show info message
 */

function showinfo(info) {
  dialog.showMessageBox({
    type: 'info',
    title: 'elfocrypt',
    message: `\n${info}`,
    buttons: ['ok']
  });
}

/**
 * create windows
 */

function create_win() {
  // login window
  login_win = new BrowserWindow({
    width: 600,
    height: 400,
    'min-width': 400,
    'min-height': 200,
    icon: iconpath
  });

  // by default, load login window
  login_win.loadURL(login_index);

  // open devtool for debugging
  //login_win.webContents.openDevTools();

  // dereference window when it is closed
  login_win.on('closed', () => {
    login_win = null;
  });

  // verify friend window
  getfrd_win = new BrowserWindow({
    width: 700,
    height: 500,
    'min-width': 400,
    'min-height': 200,
    icon: iconpath,
    show: false
  });
  getfrd_win.on('closed', () => {
    getfrd_win = null;
  });

  // friend request window
  sendfrd_win = new BrowserWindow({
    width: 700,
    height: 500,
    'min-width': 400,
    'min-height': 200,
    icon: iconpath,
    show: false
  });
  sendfrd_win.on('closed', () => {
    sendfrd_win = null;
  });

  // chat window, authenticated route
  chat_win = new BrowserWindow({
    width: 1000,
    height: 550,
    'min-width': 400,
    'min-height': 200,
    icon: iconpath,
    show: false
  });

  chat_win.on('closed', () => {
    if (getfrd_win !== null) {
      getfrd_win.close();
    }
    if (sendfrd_win !== null) {
      sendfrd_win.close();
    }
    auth.logout((err) => {
      if (err) {
        console.log('logout-err: ', err);
        showerr(err);
      }
      chat_win = null;
      app.quit();
    });
  });  
}

/**
 * load chat window
 */

function load_chat() {    
  chat_win.loadURL(chat_index);
  //chat_win.webContents.openDevTools();
  chat_win.show();
}

function load_sendfrd() {
  sendfrd_win.loadURL(sendfrd_index);
  //sendfrd_win.webContents.openDevTools();
  sendfrd_win.show();
}

function load_verify_frd() {
  getfrd_win.loadURL(getfrd_index);
  //getfrd_win.webContents.openDevTools();
  getfrd_win.show();
  getfrd_win.focus();
}

app.on('ready', create_win);

/**
 * when all windows are closed, quit the app
 */

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {  
    app.quit();
  }
});

app.on('activate', () => {
  if (login_win === null) {
    create_win();
  }
});

/**
 * load add friend window
 */

ipcMain.on('load-sendfrd', () => {
  load_sendfrd();
});

/**
 * reload login window on error
 */

ipcMain.on('login-err', (event, err) => {
  showerr(err);
  login_win.reload();
});

ipcMain.on('sendfrd-err', (event, err) => {
  showerr(err);
  sendfrd_win.reload();
});

/**
 * reload add friend window on error
 */

ipcMain.on('getfrd-err', (event, err) => {
  showerr(err);
  getfrd_win.reload();
});

/**
 * reload chat window on I/O error
 */

ipcMain.on('chat-err', (event, err) => {
  showerr(err);
  chat_win.reload();
});

/**
 * make a request to /login endpoint
 * if successful, load chat window
 */

ipcMain.on('request-login', (ev, dat) => {
  if (dat.usern && dat.passw) {
    auth.login(dat.usern, dat.passw, (err) => {
      if (err) {
        showerr(err);
        login_win.reload();
      } else {
        load_chat();
        if (login_win !== null) {
          login_win.close();
        }
      }
    });
  } else {
    showerr('username/password not valid');
  }
});

/**
 * add new friend event
 */

ipcMain.on('send-frd-req', (ev, dat) => {
  if (dat.frd_un && dat.sec) {
    auth.send_frd_req(dat.frd_un, dat.sec, (err) => {
      if (err) {
        showerr(err);
        sendfrd_win.reload();
      } else {
        if (sendfrd_win !== null) {
          sendfrd_win.hide();
        }
      }
    });
  } else {
    showerr('invalid username/secret');
    chat_win.reload();
  }
});

ipcMain.on('fetch-frd-req', (ev) => {
  frd_req_timer = setInterval(() => {
    auth.fetch_frd_req((err, req) => {
      if (err) {
        showerr(err);
        chat_win.reload();
      }
      if (req) {
        ev.sender.send('fetch-frd-req-success');
      }
    });
  }, 5000);
});

ipcMain.on('show-frd-req', () => {
  var ans;
  auth.get_frd_req((err, req) => {
    if (err) {
      showerr(err);
      chat_win.reload();
    }
    ans = dialog.showMessageBox({
      type: 'info',
      title: 'friend request',
      message: `\n${req.sen} wants to add you as a friend. Do you accept?`,
      buttons: ['no', 'yes']
    });
    if (ans === 0) {
      auth.send_frd_rej(req.sen, (err) => {
        if (err) {
          showerr(err);
        } else {
          showinfo(`A reject response sent to ${req.sen}`);
          chat_win.focus();
        }
      });
    } else {    
      load_verify_frd();
    }
  });
});

ipcMain.on('verify-frd-req', (ev, dat) => {
  if (dat.frd_un && dat.sec) {
    auth.verify_frd_req(dat.frd_un, dat.sec, (err) => {
      if (err) {
        showerr(err);
      } else {    
        showinfo(`${dat.frd_un} verified and added successfully`);
        getfrd_win.hide();
        chat_win.reload();
      }
    });
  }
});

ipcMain.on('fetch-frd-rej', (ev) => {
  frd_rej_timer = setInterval(() => {
  auth.fetch_frd_rej((err, rej) => {
    if (err) {
      showerr(err);
      chat_win.reload();
    }
    if (rej) {
      ev.sender.send('fetch-frd-rej-success');
    }
  });
  }, 5000);
});

ipcMain.on('show-frd-rej', () => {
  auth.get_frd_rej((err, rej) => {
    if (err) {
      showerr(err);
      chat_win.reload();
    }
    auth.clear_frd_rej_loc((err) => {
      if (err) {
        showerr(err);
        chat_win.reload();
      } else {
        showinfo(`${rej} rejected your friend request`);
      }
    });
  });
});

/**
 * send friend list to ipc renderer event
 */

ipcMain.on('frd-ls', (ev) => {
  auth.get_frds((err, frds) => {
    if (err) {
      showerr(err);
      if (chat_win !== null) {
        chat_win.reload();
      }
    }
    if (frds) {
      ev.sender.send('frd-ls-success', frds);
    }
  });
});

/**
 * send message event
 */

ipcMain.on('send-msg', (ev, dat) => {
  if (dat.msg && dat.receiver) {
    auth.send_msg(dat.msg, dat.receiver, (err, res) => {
      if (err) {
        showerr(err);
        if (chat_win !== null) {
          chat_win.reload();
        }
      }
      if (res.un && res.time) {
        ev.sender.send('send-msg-success', {
          un: res.un,
          msg: dat.msg,
          time: res.time
        });
      }
    });
  }
});

/**
 * fetch unread messages and return an array of successfully 
 * decrypted messages to ipc renderer for showing to the user
 */

ipcMain.on('fetch-unread', (ev) => {
  unread_timer = setInterval(() => {
    auth.fetch_unread((err, unread) => {
      if (err) {
        showerr(err);
        chat_win.reload();
      }
      if (unread) {    
        ev.sender.send('fetch-unread-success', unread);
      }
    });
  }, 3000);
});

/**
 * logout event
 */

ipcMain.on('logout', () => {
  clearInterval(frd_req_timer);
  clearInterval(frd_rej_timer);
  clearInterval(unread_timer);
  auth.logout((err) => {
    if (err) {
      showerr(err);
    }
    app.quit();
  });
});

/**
 * if something unexpected happens, show the error
 */

process.on('uncaughtException', (err) => {
  console.log('unex-err:', err);
  console.log(`something unexpected happened: ${err}`);
  showerr(err.message);
});
