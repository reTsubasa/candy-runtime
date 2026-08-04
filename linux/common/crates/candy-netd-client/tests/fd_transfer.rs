use candy_netd_client::{recv_response, send_response};
use candy_netd_proto::{NetdResponse, ResponseBody};
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

#[test]
fn response_frame_transfers_exactly_one_owned_fd() {
    let (left, right) = UnixStream::pair().unwrap();
    let file = File::open("/dev/null").unwrap();
    let response = NetdResponse {
        request_id: 9,
        body: ResponseBody::Prepared {
            generation: 7,
            tun_fd_attached: true,
        },
    };
    let sent_response = response.clone();
    let sender = std::thread::spawn(move || {
        send_response(&left, &sent_response, Some(file.as_raw_fd())).unwrap();
    });
    let (actual, fd): (NetdResponse, Option<OwnedFd>) = recv_response(&right).unwrap();
    sender.join().unwrap();
    assert_eq!(actual, response);
    assert!(fd.is_some());
}

#[test]
fn response_without_fd_rejects_a_claim_that_one_is_attached() {
    let (left, right) = UnixStream::pair().unwrap();
    let response = NetdResponse {
        request_id: 9,
        body: ResponseBody::Prepared {
            generation: 7,
            tun_fd_attached: true,
        },
    };
    let sender = std::thread::spawn(move || send_response(&left, &response, None));
    assert!(recv_response(&right).is_err());
    assert!(sender.join().unwrap().is_err());
}

#[test]
fn response_frame_handles_segmented_stream_reads() {
    let (mut left, right) = UnixStream::pair().unwrap();
    let response = NetdResponse {
        request_id: 12,
        body: ResponseBody::Committed { generation: 7 },
    };
    let payload = response.encode().unwrap();
    let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&payload);
    let sender = std::thread::spawn(move || {
        for byte in frame {
            left.write_all(&[byte]).unwrap();
        }
    });
    let (actual, descriptor) = recv_response(&right).unwrap();
    sender.join().unwrap();
    assert_eq!(actual, response);
    assert!(descriptor.is_none());
}

#[test]
fn response_rejects_multiple_descriptors() {
    use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};
    use std::io::IoSlice;

    let (left, right) = UnixStream::pair().unwrap();
    let first = File::open("/dev/null").unwrap();
    let second = File::open("/dev/null").unwrap();
    let response = NetdResponse {
        request_id: 13,
        body: ResponseBody::Prepared {
            generation: 7,
            tun_fd_attached: true,
        },
    };
    let payload = response.encode().unwrap();
    let length = (payload.len() as u32).to_be_bytes();
    let slices = [IoSlice::new(&length), IoSlice::new(&payload)];
    let descriptors = [first.as_raw_fd(), second.as_raw_fd()];
    sendmsg::<()>(
        left.as_raw_fd(),
        &slices,
        &[ControlMessage::ScmRights(&descriptors)],
        MsgFlags::empty(),
        None,
    )
    .unwrap();
    assert!(recv_response(&right).is_err());
}
