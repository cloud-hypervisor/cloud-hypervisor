use std::sync::Mutex;

pub struct MigrationDataFile {
    data: Mutex<(Vec<u8>, bool)>,
}

impl MigrationDataFile {
    pub fn new() -> Self {
        //TODO: Capacity 32 is for test. It should be 32 * 1024.
        let v: Vec<u8> = Vec::with_capacity(32);
        let r: bool = false;
        MigrationDataFile { data: Mutex::new((v, r)) }
    }

    pub fn write(&self, entry: &mut Vec<u8>, recv: bool) {
        if let Ok(mut data_lock) = self.data.lock() {
            let (ref mut data, ref mut rv) = *data_lock;
            let len = entry.len();
            let data_len = data.len();

            if (data_len + len) >= data.capacity() {
                println!("write: achieve capacity, exit.");
                return;
            }

            data.append(entry);

            // recv means if data if input from tcp server side.
            // rv is used to identify if the server tcp receiver thread
            // has received data which need be handled. It is not useful
            // on client side.
            *rv = recv;
        } else {
            println!("write: fail to get lock");
        }
    }

    pub fn read(&self, entry: &mut Vec<u8>) {
        if let Ok(mut data_lock) = self.data.lock() {
            let (ref mut data, ref mut rv) = *data_lock;

            entry.append(data);

            // Server side reads all data once.
            *rv = false;
        } else {
            println!("read: fail to get lock");
        }
    }

    pub fn data_valid(&self) -> bool {
        if let Ok(mut data_lock) = self.data.lock() {
            let (ref mut data, _) = *data_lock;
            if data.len() > 0 {
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    pub fn data_avail(&self) -> bool {
        if let Ok(mut data_lock) = self.data.lock() {
            let (_, ref mut rv) = *data_lock;
            *rv
        } else {
            println!("avail: fail to get lock");
            false
        }
    }
}
