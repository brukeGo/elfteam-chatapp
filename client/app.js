'use strict';

const path = require('path');
const electron = require('electron');
const {app, BrowserWindow, dialog, ipcMain} = electron;
const iconpath = path.join(__dirname, 'resources', 'appicon.png');
const auth = require('./auth.js');

const login_index = `file://${__dirname}/views/login.html`;
const reg_index = `file://${__dirname}/views/reg.html`;
const getfrd_index = `file://${__dirname}/views/get_frd_req.html`;
const sendfrd_index = `file://${__dirname}/views/send_frd_req.html`;
const main_index = `file://${__dirname}/views/main_win.html`;

var login_win = null;
var sendfrd_win = null;
var getfrd_win = null;
var main_win = null;

var frd_req_timer;
var frd_rej_timer;
var unread_timer;

function showerr(er) {
  dialog.showMessageBox({
    type: 'error',
    title: 'elfocrypt error',
    message: `\n${er.message}`,
    buttons: ['ok']
  });
}

function showinfo(info) {
  dialog.showMessageBox({
    type: 'info',
    title: 'elfocrypt',
    message: `\n${info}`,
    buttons: ['ok']
  });
}

function create_win() {
  login_win = new BrowserWindow({
    width: 600,
    height: 300,
    'min-width': 400,
    'min-height': 200,
    icon: iconpath,
    show: false
  });

  login_win.on('closed', () => {
    login_win = null;
    app.quit();
  });

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

  main_win = new BrowserWindow({
    width: 1000,
    height: 600,
    'min-width': 400,
    'min-height': 200,
    icon: iconpath,
    show: false
  });

  main_win.on('closed', () => {
    if (login_win !== null) {
      login_win.close();
    } 
    if (getfrd_win !== null) {
      getfrd_win.close();
    }
    if (sendfrd_win !== null) {
      sendfrd_win.close();
    } 
    auth.logout(() => {
      main_win = null;
      app.quit();
    });
  });
}

function load_reg() {    
  login_win.loadURL(reg_index);
  login_win.show();
}

function load_login() {    
  login_win.loadURL(login_index);
  login_win.show();
}

function load_main() {    
  main_win.loadURL(main_index);
  main_win.show();
}

function load_sendfrd() {
  sendfrd_win.loadURL(sendfrd_index);
  sendfrd_win.show();
}

function load_verify_frd() {
  getfrd_win.loadURL(getfrd_index);
  getfrd_win.show();
  getfrd_win.focus();
}

function init() {
  create_win();
  auth.is_reg_user((y) => {
    if (y) {
      load_login();
    } else {
      load_reg();
    }
  });
}

app.on('ready', () => {
  init();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {  
    app.quit();
  }
});

app.on('activate', () => {
  if (login_win === null) {
    init();
  }
});

ipcMain.on('load-sendfrd', () => {
  load_sendfrd();
});

ipcMain.on('login-err', (event, err) => {
  showerr(err);
  login_win.reload();
});

ipcMain.on('sendfrd-err', (event, err) => {
  showerr(err);
  sendfrd_win.reload();
});

ipcMain.on('getfrd-err', (event, err) => {
  showerr(err);
  getfrd_win.reload();
});

ipcMain.on('main-err', (event, err) => {
  showerr(err);
  main_win.reload();
});

ipcMain.on('request-reg', (ev, usern) => {
  if (usern) {
    auth.register(usern, (er) => {
      if (er) {
        showerr(er);
        login_win.reload();
      } else {
        load_login();
      }
    });
  } else {
    showerr(new Error('invalid username'));
  }
});

ipcMain.on('request-login', (ev, usern) => {
  if (usern) {
    auth.login(usern, (er) => {
      if (er) {
        showerr(er);
        login_win.reload();
      } else {
        load_main();
        if (login_win !== null) {
          login_win.hide();
        }
      }
    });
  } else {
    showerr(new Error('invalid username'));
  }
});

ipcMain.on('send-frd-req', (ev, dat) => {
  if (dat.frd_un && dat.sec) {
    auth.send_frd_req(dat.frd_un, dat.sec, (er) => {
      if (er) {
        showerr(er);
        sendfrd_win.reload();
      } else {
        if (sendfrd_win !== null) {
          sendfrd_win.hide();
        }
      }
    });
  } else {
    showerr(new Error('invalid username/secret'));
    main_win.reload();
  }
});

ipcMain.on('fetch-frd-req', () => {
  frd_req_timer = setInterval(() => {
    auth.fetch_frd_req((er, sen) => {
      var ans;
      if (er) {
        showerr(er);
        main_win.reload();
      }
      if (sen) {
        ans = dialog.showMessageBox({
          type: 'info',
          title: 'friend request',
          message: `\n${sen} wants to add you as a friend. Do you accept?`,
          buttons: ['no', 'yes']
        });
        if (ans === 0) {
          auth.send_frd_rej(sen, (er) => {
            if (er) {
              showerr(er);
            } else {
              showinfo(`A reject response sent to ${sen}`);
              main_win.focus();
            }
          });
        } else {
          load_verify_frd();
        }
      }
    });
  }, 7000);
});

ipcMain.on('verify-frd-req', (ev, dat) => {
  if (dat.frd_un && dat.sec) {
    auth.verify_frd_req(dat.frd_un, dat.sec, (er) => {
      if (er) {
        showerr(er);
      } else {
        showinfo(`${dat.frd_un} verified and added successfully`);
        getfrd_win.hide();
        main_win.reload();
      }
    });
  } else {
    showerr(new Error('null friend username and/or shared secret'));
  }
});

ipcMain.on('fetch-frd-rej', () => {
  frd_rej_timer = setInterval(() => {
    auth.fetch_frd_rej((er, rej) => {
      if (er) {
        showerr(er);
        main_win.reload();
      }
      if (rej) {
        showinfo(`${rej} rejected your friend request`);
      }
    });
  }, 7000);
});

ipcMain.on('frd-ls', (ev) => {
  auth.get_frds((er, frds) => {
    if (er) {
      showerr(er);
      if (main_win !== null) {
        main_win.reload();
      }
    }
    if (frds) {
      ev.sender.send('frd-ls-success', frds);
    }
  });
});

ipcMain.on('send-msg', (ev, dat) => {
  if (dat.msg && dat.receiver) {
    auth.send_msg(dat.msg, dat.receiver, (er, res) => {
      if (er) {
        showerr(er);
        if (main_win !== null) {
          main_win.reload();
        }
      }
      if (res) {
        ev.sender.send('send-msg-success', res);
      }
    });
  } else {
    showerr(new Error('null message and/or receiver'));
  }
});

ipcMain.on('fetch-unread', (ev) => {
  unread_timer = setInterval(() => {
    auth.fetch_unread((er, unread) => {
      if (er) {
        showerr(er);
        main_win.reload();
      }
      if (unread) {    
        ev.sender.send('fetch-unread-success', unread);
      }
    });
  }, 7000);
});

ipcMain.on('logout', () => {
  clearInterval(frd_req_timer);
  clearInterval(frd_rej_timer);
  clearInterval(unread_timer);
  auth.logout((er) => {
    if (er) showerr(er);
    app.quit();
  });
});

process.on('uncaughtException', (er) => {
  console.log('unex-err:', er);
  showerr(er);
  app.quit();
});
