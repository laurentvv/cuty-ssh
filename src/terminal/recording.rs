//! Asciinema v2 (`.cast`) terminal session recording and playback engine.
//!
//! Provides lightweight, JSON Lines-based session recording compatible with
//! standard `asciinema play` and the in-app Cuty-SSH Replay Player.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Asciinema v2 header definition (first line of a `.cast` file).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsciinemaHeader {
    pub version: u32,
    pub width: usize,
    pub height: usize,
    pub timestamp: u64,
    pub title: String,
    #[serde(default)]
    pub env: AsciinemaEnv,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AsciinemaEnv {
    #[serde(default = "default_term")]
    pub term: String,
    #[serde(default = "default_shell")]
    pub shell: String,
}

fn default_term() -> String {
    "xterm-256color".to_string()
}

fn default_shell() -> String {
    "/bin/bash".to_string()
}

/// A recorded event in the stream: `[time_offset_seconds, event_type, data]`.
#[derive(Debug, Clone)]
pub struct RecordedEvent {
    pub time_offset: f64,
    pub event_type: String, // "o" for stdout/output, "i" for stdin/input
    pub data: String,
}

/// Active session recorder writing incrementally to a `.cast` file.
pub struct SessionRecorder {
    pub file_path: PathBuf,
    file: File,
    start_time: Instant,
    pub event_count: usize,
    pub bytes_written: usize,
}

impl SessionRecorder {
    /// Start recording a new session to `cuty-ssh-portable/recordings/<sanitized_name>_<timestamp>.cast`.
    pub fn start(session_name: &str, cols: usize, rows: usize) -> Result<Self> {
        let base_dir = PathBuf::from("cuty-ssh-portable").join("recordings");
        let _ = std::fs::create_dir_all(&base_dir);

        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let sanitized: String = session_name
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let file_name = format!("{}_{}.cast", sanitized, now_unix);
        let file_path = base_dir.join(file_name);

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&file_path)
            .with_context(|| format!("Failed to create recording file: {}", file_path.display()))?;

        let header = AsciinemaHeader {
            version: 2,
            width: cols.max(40),
            height: rows.max(10),
            timestamp: now_unix,
            title: format!("Cuty-SSH Session: {}", session_name),
            env: AsciinemaEnv {
                term: "xterm-256color".to_string(),
                shell: "/bin/bash".to_string(),
            },
        };

        let header_json = serde_json::to_string(&header)?;
        writeln!(file, "{}", header_json)?;

        Ok(Self {
            file_path,
            file,
            start_time: Instant::now(),
            event_count: 0,
            bytes_written: header_json.len() + 1,
        })
    }

    /// Record terminal output from the remote host or local PTY.
    pub fn record_output(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let data = String::from_utf8_lossy(bytes).to_string();

        let event = serde_json::json!([elapsed, "o", data]);
        if let Ok(line) = serde_json::to_string(&event)
            && writeln!(self.file, "{}", line).is_ok()
        {
            self.event_count += 1;
            self.bytes_written += line.len() + 1;
        }
    }

    /// Record keystrokes or input sent to the session.
    pub fn record_input(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let data = String::from_utf8_lossy(bytes).to_string();

        let event = serde_json::json!([elapsed, "i", data]);
        if let Ok(line) = serde_json::to_string(&event)
            && writeln!(self.file, "{}", line).is_ok()
        {
            self.event_count += 1;
            self.bytes_written += line.len() + 1;
        }
    }

    /// Total recording duration elapsed so far.
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Stop and flush the recording.
    pub fn stop(mut self) -> Result<PathBuf> {
        self.file.flush()?;
        Ok(self.file_path)
    }
}

/// In-memory player for an asciinema `.cast` file.
pub struct SessionPlayer {
    pub header: AsciinemaHeader,
    pub events: Vec<RecordedEvent>,
    pub file_path: PathBuf,
    pub current_time: f64,
    pub total_duration: f64,
    pub current_event_idx: usize,
    pub is_playing: bool,
    pub speed: f32,
}

impl SessionPlayer {
    /// Load and parse a `.cast` file into memory.
    pub fn load_file(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        let first_line = lines
            .next()
            .ok_or_else(|| anyhow::anyhow!("Empty recording file"))??;
        let header: AsciinemaHeader = serde_json::from_str(&first_line)
            .context("Invalid asciinema v2 header in first line")?;

        let mut events = Vec::new();
        let mut max_time = 0.0f64;

        for line_res in lines {
            let line = line_res?;
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&line)
                && let Some(arr) = parsed.as_array()
                && arr.len() >= 3
            {
                let t = arr[0].as_f64().unwrap_or(0.0);
                let ev_type = arr[1].as_str().unwrap_or("o").to_string();
                let data = arr[2].as_str().unwrap_or("").to_string();
                if t > max_time {
                    max_time = t;
                }
                events.push(RecordedEvent {
                    time_offset: t,
                    event_type: ev_type,
                    data,
                });
            }
        }

        Ok(Self {
            header,
            events,
            file_path: path.to_path_buf(),
            current_time: 0.0,
            total_duration: max_time,
            current_event_idx: 0,
            is_playing: false,
            speed: 1.0,
        })
    }

    /// Advance time by `dt` seconds and return all output chunks to feed to the terminal canvas.
    pub fn advance(&mut self, dt: f64) -> Vec<String> {
        if !self.is_playing || self.events.is_empty() {
            return Vec::new();
        }

        self.current_time += dt * (self.speed as f64);
        if self.current_time >= self.total_duration {
            self.current_time = self.total_duration;
            self.is_playing = false;
        }

        let mut chunks = Vec::new();
        while self.current_event_idx < self.events.len() {
            let ev = &self.events[self.current_event_idx];
            if ev.time_offset <= self.current_time {
                if ev.event_type == "o" {
                    chunks.push(ev.data.clone());
                }
                self.current_event_idx += 1;
            } else {
                break;
            }
        }

        chunks
    }

    /// Seek to a specific timestamp in seconds (resets event index and returns all output up to that time).
    pub fn seek_to(&mut self, target_seconds: f64) -> Vec<String> {
        self.current_time = target_seconds.clamp(0.0, self.total_duration);
        self.current_event_idx = 0;
        let mut chunks = Vec::new();

        while self.current_event_idx < self.events.len() {
            let ev = &self.events[self.current_event_idx];
            if ev.time_offset <= self.current_time {
                if ev.event_type == "o" {
                    chunks.push(ev.data.clone());
                }
                self.current_event_idx += 1;
            } else {
                break;
            }
        }

        chunks
    }

    /// Restart playback from the beginning.
    pub fn restart(&mut self) {
        self.current_time = 0.0;
        self.current_event_idx = 0;
        self.is_playing = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asciinema_recording_and_playback_roundtrip() {
        let temp_dir =
            std::env::temp_dir().join(format!("cuty_test_cast_{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let test_file = temp_dir.join("test_session.cast");

        // Write sample asciinema v2 content
        {
            let mut file = File::create(&test_file).unwrap();
            let header = AsciinemaHeader {
                version: 2,
                width: 80,
                height: 24,
                timestamp: 1700000000,
                title: "Test Session".to_string(),
                env: AsciinemaEnv {
                    term: "xterm-256color".to_string(),
                    shell: "/bin/bash".to_string(),
                },
            };
            writeln!(file, "{}", serde_json::to_string(&header).unwrap()).unwrap();
            writeln!(file, "{}", serde_json::json!([0.1, "o", "Hello "])).unwrap();
            writeln!(file, "{}", serde_json::json!([0.5, "i", "ls\n"])).unwrap();
            writeln!(file, "{}", serde_json::json!([0.8, "o", "World!\r\n"])).unwrap();
        }

        let mut player = SessionPlayer::load_file(&test_file).expect("Failed to load cast");
        assert_eq!(player.header.version, 2);
        assert_eq!(player.header.width, 80);
        assert_eq!(player.events.len(), 3);
        assert!((player.total_duration - 0.8).abs() < 1e-4);

        // Test advance
        player.is_playing = true;
        let out1 = player.advance(0.2);
        assert_eq!(out1, vec!["Hello "]);

        let out2 = player.advance(0.7);
        assert_eq!(out2, vec!["World!\r\n"]);

        // Test seek
        let seek_out = player.seek_to(0.2);
        assert_eq!(seek_out, vec!["Hello "]);

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
