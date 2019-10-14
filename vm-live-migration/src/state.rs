use std::thread;
use std::io;
use std::sync::{Arc, Mutex};
use crossbeam_channel::unbounded;
use crossbeam::channel::{Sender, Receiver};

use crate::data::MigrationDataFile;

/// Errors associated with state management
#[derive(Debug)]
pub enum Error {
    /// Cannot spawn a new data receive thread.
    DataReceiveSpawn(io::Error),

    /// Cannot spawn a new send state thread.
    SendStateSpawn(io::Error),
}

#[derive(Clone)]
pub struct MigrationState {
    msg_send: Sender<Vec<u8>>,
    msg_recv: Receiver<Vec<u8>>,
    data_send: Sender<Vec<u8>>,
    data_recv: Receiver<Vec<u8>>,
}

impl MigrationState {
    pub fn new() -> Self {
        let (ms, mr) = unbounded();
        let (ds, dr) = unbounded();

        MigrationState {
            msg_send: ms,
            msg_recv: mr,
            data_send: ds,
            data_recv: dr,
        }
    }

    pub fn m_send(&self, msg: Vec<u8>) {
        let sender = self.msg_send.clone();
        let s = thread::spawn(move || {
            sender.send(msg).unwrap();
        });
        s.join().expect("Msg sender thread cannot join");
    }

    pub fn m_recv(&self) -> Vec<u8> {
        let receiver = self.msg_recv.clone();
        receiver.recv().unwrap()
    }

    pub fn d_send(&self, msg: Vec<u8>) {
        let sender = self.data_send.clone();
        let s = thread::spawn(move || {
            sender.send(msg).unwrap();
        });
        s.join().expect("Sender thread cannot join");
    }

    pub fn d_recv(&self, data: Arc<MigrationDataFile>) {
        let receiver = self.data_recv.clone();
        let data1 = data.clone();

        thread::Builder::new()
            .name(format!("receive_{}", "data"))
            .spawn(move || {
                loop {
                    let mut msg = receiver.recv().unwrap();
                    data1.write(&mut msg, false);
                }
            })
            .map_err(Error::DataReceiveSpawn);
    }

    /* Caller should create thread by itself to receive and handle data */
    pub fn d_recv_return(&self) -> Vec<u8> {
        let receiver = self.data_recv.clone();
        let data = receiver.recv().unwrap();
        data
    }
}

pub trait MigrationStateFn {
    /* Input cloned MigrationState instance */
    fn register_state(&self, s: MigrationState) {
        migration_state_push(s);
    }

    /* Input cloned MigrationState instance */
    fn send_state(&self, s: MigrationState, d: Vec<u8>) {
        let state = s.clone();
        let data = d.clone();
        thread::Builder::new()
            .name(format!("send_state"))
            .spawn(move || {
                let msg = state.m_recv();
                if msg[0] == 1 {
                    state.d_send(data);
                }
            })
            .map_err(Error::SendStateSpawn);
    }

    /* Implemented by struct itself:
     * 1. create a thread;
     * 2. call d_recv_return() to return the received data;
     * 3. parse data and set field value.
     */
    fn load_state(&mut self);
}

lazy_static! {
    static ref MIG_STATE_ARRAY: Arc<Mutex<Vec<MigrationState>>> = Arc::new(Mutex::new(vec![]));
}

pub fn migration_state_push(state: MigrationState) {
    MIG_STATE_ARRAY.lock().unwrap().push(state);
}

pub fn migration_state_pop() -> MigrationState {
    MIG_STATE_ARRAY.lock().unwrap().pop().expect("Cannot find MigrationState")
}
