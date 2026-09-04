use std::time::{Duration, Instant};

use pad_gateway::agent::replay_timeline;
use pad_gateway::pcap::read_udp;
use pad_gateway::protocol::{
    audio_packet, session_control, split_coalesced, Endpoints, JpegReassembler, Message,
    FAMILY_SESSION, MEDIA_AUDIO, OP_ANSWER, OP_MEDIA, OP_UNLOCK,
};
use pad_gateway::state::{CallMachine, CallPhase, Owner, StateError};
use pad_gateway::transport::{AgentEvent, FrameKind};

#[test]
fn captured_session_and_media_are_decoded() {
    let records = read_udp("testdata/pad.cap").expect("read capture");
    let mut calls = 0;
    let mut answers = 0;
    let mut unlocks = 0;
    let mut audio = 0;
    let mut jpeg = JpegReassembler::default();
    let mut jpeg_frames = 0;

    for record in &records {
        for raw in split_coalesced(&record.payload) {
            let Ok(message) = Message::parse(raw) else {
                continue;
            };
            if message.family != FAMILY_SESSION {
                continue;
            }
            calls += usize::from(message.opcode == 1);
            answers += usize::from(message.opcode == OP_ANSWER);
            unlocks += usize::from(message.opcode == OP_UNLOCK);
            if message.opcode == OP_MEDIA {
                let media = message.media().expect("media header");
                if media.media_type == MEDIA_AUDIO {
                    assert_eq!(media.valid_length, 512);
                    audio += 1;
                } else if jpeg.push(&media).is_some() {
                    jpeg_frames += 1;
                }
            }
        }
    }
    // The door retransmits the same logical call request three times.
    assert_eq!(calls, 3);
    assert_eq!(answers, 1);
    // The user pressed twice, but the capture contains one effective datagram.
    assert_eq!(unlocks, 1);
    assert_eq!(jpeg_frames, 230);
    assert!(audio > 100);
}

#[test]
fn production_encoder_round_trips() {
    let endpoints = Endpoints::captured();
    let answer = session_control(OP_ANSWER, &endpoints).unwrap();
    let message = Message::parse(&answer).unwrap();
    assert_eq!(message.declared, 80);
    assert_eq!(message.endpoints().unwrap(), endpoints);

    let pcm = [0x5a; 512];
    let packet = audio_packet(42, &pcm, &endpoints).unwrap();
    let media = Message::parse(&packet).unwrap().media().unwrap();
    assert_eq!(media.sequence, 42);
    assert_eq!(media.data, pcm);
}

#[test]
fn replay_timeline_decodes_events_and_media() {
    let timeline = replay_timeline("testdata/pad.cap").unwrap();
    assert_eq!(timeline.len(), 334);
    // The first frame is a control event that decodes back to CallStarted.
    assert_eq!(timeline[0].frame.kind, FrameKind::Event);
    assert!(matches!(
        timeline[0].frame.decode_cbor::<AgentEvent>().unwrap(),
        AgentEvent::CallStarted { .. }
    ));
    assert_eq!(
        timeline
            .iter()
            .filter(|item| item.frame.kind == FrameKind::Jpeg)
            .count(),
        230
    );
    assert_eq!(
        timeline
            .iter()
            .filter(|item| item.frame.kind == FrameKind::DoorPcm)
            .count(),
        100
    );
    assert_eq!(timeline.last().unwrap().offset_micros, 10_950_493);
}

#[test]
fn unlock_is_allowed_any_time_with_cooldown() {
    let mut state = CallMachine::new(Duration::from_secs(1));
    let now = Instant::now();
    state.unlock(now).unwrap();
    assert_eq!(state.unlock(now), Err(StateError::UnlockCooldown));
    state.start_call(7);
    assert_eq!(
        state.unlock(now + Duration::from_secs(2)),
        Ok(()),
        "ringing calls can be unlocked without answering"
    );
    state.pad_answer().unwrap();
    assert_eq!(state.unlock(now + Duration::from_secs(4)), Ok(()));
}

#[test]
fn strict_policy_requires_remote_owner_before_unlock() {
    let mut state = CallMachine::with_policy(Duration::from_secs(1), true);
    state.start_call(7);
    assert_eq!(
        state.unlock(Instant::now()),
        Err(StateError::UnlockNotAllowed)
    );
    state.remote_answer().unwrap();
    let now = Instant::now();
    state.unlock(now).unwrap();
    assert_eq!(state.unlock(now), Err(StateError::UnlockCooldown));
    assert_eq!(state.state().phase, CallPhase::Connected);
    assert_eq!(state.state().owner, Owner::Remote);
}
