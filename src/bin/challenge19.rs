use crossterm::cursor::MoveTo;
use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::terminal::{Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::{ExecutableCommand, QueueableCommand};
use rand::RngCore;
use std::error::Error;
use std::io::{Stdout, Write};

const ENCODED_CLEARTEXT: &str = include_str!("../../data/challenge19.txt");

fn main() -> Result<(), Box<dyn Error>> {
    let key = {
        let mut key = [0; 16];
        rand::thread_rng().fill_bytes(&mut key);

        key
    };

    let ciphertexts: Vec<Vec<u8>> = ENCODED_CLEARTEXT
        .lines()
        .map(|line| {
            radix64::STD
                .decode(line)
                .map(|decoded| cryptopals::aes::aes_ctr_transform(&decoded, &key, 0))
        })
        .collect::<Result<_, _>>()?;

    let mut decryption_app = DecryptionTerminalApp::new(ciphertexts, std::io::stdout());
    decryption_app.run()?;

    Ok(())
}

struct DecryptionTerminalApp {
    ciphertexts: Vec<Vec<u8>>,
    keystream: Vec<Option<u8>>,

    stdout: Stdout,

    cursor_position: (u16, u16),
}

impl DecryptionTerminalApp {
    fn new(ciphertexts: Vec<Vec<u8>>, stdout: Stdout) -> Self {
        let max_length = ciphertexts
            .iter()
            .map(|ciphertext| ciphertext.len())
            .max()
            .unwrap();

        Self {
            ciphertexts,
            keystream: vec![None; max_length],

            stdout,

            cursor_position: (0, 0),
        }
    }

    fn run(&mut self) -> crossterm::Result<()> {
        self.stdout.execute(EnterAlternateScreen)?;
        crossterm::terminal::enable_raw_mode()?;

        let mut needs_redraw = true;

        loop {
            if needs_redraw {
                self.redraw()?;
                needs_redraw = false;
            }

            match crossterm::event::read()? {
                Event::Key(event) => match event {
                    KeyEvent {
                        code: KeyCode::Char('c'),
                        modifiers: KeyModifiers::CONTROL,
                        ..
                    } => {
                        break;
                    }

                    KeyEvent {
                        code: KeyCode::Left,
                        ..
                    } => {
                        if self.cursor_position.0 > 0 {
                            self.cursor_position.0 -= 1;
                        }

                        self.update_cursor()?;
                    }

                    KeyEvent {
                        code: KeyCode::Right,
                        ..
                    } => {
                        if (self.cursor_position.0 as usize)
                            < self.ciphertexts[self.cursor_position.1 as usize].len() - 1
                        {
                            self.cursor_position.0 += 1;
                        }

                        self.update_cursor()?;
                    }

                    KeyEvent {
                        code: KeyCode::Up, ..
                    } => {
                        if self.cursor_position.1 > 0 {
                            self.cursor_position.1 -= 1;
                        }

                        if (self.cursor_position.0 as usize)
                            > self.ciphertexts[self.cursor_position.1 as usize].len() - 1
                        {
                            self.cursor_position.0 =
                                (self.ciphertexts[self.cursor_position.1 as usize].len() - 1)
                                    as u16;
                        }

                        self.update_cursor()?;
                    }

                    KeyEvent {
                        code: KeyCode::Down,
                        ..
                    } => {
                        if (self.cursor_position.1 as usize) < self.ciphertexts.len() - 1 {
                            self.cursor_position.1 += 1;
                        }

                        if (self.cursor_position.0 as usize)
                            > self.ciphertexts[self.cursor_position.1 as usize].len() - 1
                        {
                            self.cursor_position.0 =
                                (self.ciphertexts[self.cursor_position.1 as usize].len() - 1)
                                    as u16;
                        }

                        self.update_cursor()?;
                    }

                    KeyEvent {
                        code: KeyCode::Char(c),
                        ..
                    } => {
                        self.keystream[self.cursor_position.0 as usize] = Some(
                            self.ciphertexts[self.cursor_position.1 as usize]
                                [self.cursor_position.0 as usize]
                                ^ c as u8,
                        );

                        if (self.cursor_position.0 as usize)
                            < self.ciphertexts[self.cursor_position.1 as usize].len() - 1
                        {
                            self.cursor_position.0 += 1;
                        }

                        needs_redraw = true;
                    }

                    KeyEvent {
                        code: KeyCode::Backspace,
                        ..
                    } => {
                        self.keystream[self.cursor_position.0 as usize] = None;

                        if self.cursor_position.0 > 0 {
                            self.cursor_position.0 -= 1;
                        }

                        needs_redraw = true;
                    }

                    _ => {}
                },
                _ => continue,
            }
        }

        Ok(())
    }

    fn update_cursor(&mut self) -> crossterm::Result<()> {
        self.stdout
            .execute(MoveTo(self.cursor_position.0, self.cursor_position.1))?;

        Ok(())
    }

    fn redraw(&mut self) -> crossterm::Result<()> {
        self.stdout.queue(Clear(ClearType::All))?;
        self.stdout.queue(MoveTo(0, 0))?;

        for ciphertext in self.ciphertexts.iter() {
            let line: String = ciphertext
                .iter()
                .zip(self.keystream.iter())
                .map(|(c, k)| {
                    if let Some(key_byte) = k {
                        (c ^ key_byte) as char
                    } else {
                        '░'
                    }
                })
                .collect();

            println!("{}\r", line);
        }

        println!();
        println!("Keystream:\r");

        println!(
            "{}",
            self.keystream
                .iter()
                .map(|b| match b {
                    Some(b) => format!("{:02x}", b),
                    None => "??".to_string(),
                })
                .collect::<Vec<String>>()
                .join(", ")
        );

        self.stdout
            .queue(MoveTo(self.cursor_position.0, self.cursor_position.1))?;
        self.stdout.flush()?;

        Ok(())
    }
}

impl Drop for DecryptionTerminalApp {
    fn drop(&mut self) {
        if let Ok(enabled) = crossterm::terminal::is_raw_mode_enabled() {
            if enabled {
                crossterm::terminal::disable_raw_mode().expect("Should disable raw mode");
            }
        }

        self.stdout
            .execute(LeaveAlternateScreen)
            .expect("Should leave alternate screen");
    }
}
