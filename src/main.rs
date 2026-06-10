mod app;
mod capture;
mod scanner;
mod ui;

use app::App;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> std::io::Result<()> {
    let mut terminal = ratatui::init();
    let result = app::run(&mut terminal, App::new()).await;
    ratatui::restore();
    result
}
