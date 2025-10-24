use std::io::{stdout, Stdout, Write};

use crossterm::{
    cursor::{Hide, MoveTo, Show},
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    style::{Color, Print, ResetColor, SetBackgroundColor, SetForegroundColor},
    terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
};

fn main() -> std::io::Result<()> {
    let mut stdout = stdout();
    terminal::enable_raw_mode()?;
    execute!(stdout, EnterAlternateScreen, Hide)?;

    let selected = run_app(&mut stdout);

    execute!(stdout, Show, LeaveAlternateScreen)?;
    terminal::disable_raw_mode()?;

    match selected {
        Ok(value) => println!("You selected {value}"),
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    }

    Ok(())
}

fn run_app(stdout: &mut Stdout) -> Result<u8, String> {
    let values: Vec<u8> = (1..=10).collect();
    let mut index = 0usize;

    loop {
    draw(stdout, index, &values).map_err(|err| err.to_string())?;

        match event::read() {
            Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => match key.code {
                KeyCode::Up | KeyCode::Left => {
                    if index == 0 {
                        index = values.len() - 1;
                    } else {
                        index -= 1;
                    }
                }
                KeyCode::Down | KeyCode::Right => {
                    index = (index + 1) % values.len();
                }
                KeyCode::Enter => return Ok(values[index]),
                KeyCode::Esc => return Err("Selection cancelled".to_string()),
                KeyCode::Char('q') | KeyCode::Char('Q') => {
                    return Err("Selection cancelled".to_string())
                }
                _ => {}
            },
            Ok(_) => {}
            Err(err) => return Err(err.to_string()),
        }
    }
}

fn draw(stdout: &mut Stdout, index: usize, values: &[u8]) -> std::io::Result<()> {
    execute!(stdout, MoveTo(0, 0), Clear(ClearType::All))?;
    execute!(
        stdout,
        Print("Use the arrow keys to pick a value, then press Enter. Press Esc or q to cancel.\r\n\r\n"),
        Print("+-------+\r\n"),
        Print("| Value |\r\n"),
        Print("+-------+\r\n"),
    )?;

    for (i, value) in values.iter().enumerate() {
        if i == index {
            execute!(
                stdout,
                SetForegroundColor(Color::Black),
                SetBackgroundColor(Color::Cyan),
                Print(format!("| {:>5} |\r\n", value)),
                ResetColor
            )?;
        } else {
            execute!(stdout, Print(format!("| {:>5} |\r\n", value)))?;
        }
    }

    execute!(
        stdout,
        Print("+-------+\r\n\r\n"),
        Print("Waiting for selection...\r\n")
    )?;
    stdout.flush()?;
    Ok(())
}
