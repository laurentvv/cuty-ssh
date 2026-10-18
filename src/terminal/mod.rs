pub mod recording;

use egui::Color32;
use std::collections::VecDeque;
use vte::{Params, Parser, Perform};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CellColor {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub is_default: bool,
}

impl CellColor {
    pub const fn default_color() -> Self {
        Self {
            r: 0,
            g: 0,
            b: 0,
            is_default: true,
        }
    }

    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self {
            r,
            g,
            b,
            is_default: false,
        }
    }

    pub fn to_color32(self, fallback: Color32) -> Color32 {
        if self.is_default {
            fallback
        } else {
            Color32::from_rgb(self.r, self.g, self.b)
        }
    }
}

pub const CELL_FLAG_BOLD: u8 = 1 << 0;
pub const CELL_FLAG_DIM: u8 = 1 << 1;
pub const CELL_FLAG_ITALIC: u8 = 1 << 2;
pub const CELL_FLAG_UNDERLINE: u8 = 1 << 3;
pub const CELL_FLAG_INVERSE: u8 = 1 << 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalCell {
    pub ch: char,
    pub fg: CellColor,
    pub bg: CellColor,
    /// Packed style attributes (`CELL_FLAG_*`: bold, dim, italic, underline, inverse).
    pub flags: u8,
}

impl TerminalCell {
    #[inline]
    pub const fn bold(self) -> bool {
        (self.flags & CELL_FLAG_BOLD) != 0
    }
    #[inline]
    pub const fn dim(self) -> bool {
        (self.flags & CELL_FLAG_DIM) != 0
    }
    #[inline]
    pub const fn italic(self) -> bool {
        (self.flags & CELL_FLAG_ITALIC) != 0
    }
    #[inline]
    pub const fn underline(self) -> bool {
        (self.flags & CELL_FLAG_UNDERLINE) != 0
    }
    #[inline]
    pub const fn inverse(self) -> bool {
        (self.flags & CELL_FLAG_INVERSE) != 0
    }

    #[inline]
    pub fn set_flag(&mut self, mask: u8, enabled: bool) {
        if enabled {
            self.flags |= mask;
        } else {
            self.flags &= !mask;
        }
    }
}

impl Default for TerminalCell {
    fn default() -> Self {
        Self {
            ch: ' ',
            fg: CellColor::default_color(),
            bg: CellColor::default_color(),
            flags: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TerminalTheme {
    pub name: &'static str,
    pub bg: Color32,
    pub fg: Color32,
    pub cursor: Color32,
    pub selection_bg: Color32,
    pub ansi: [Color32; 16],
}

impl TerminalTheme {
    pub fn all_themes() -> &'static [&'static str] {
        &[
            "Cuty Dark",
            "Classic PuTTY",
            "Dracula",
            "Solarized Dark",
            "Nord",
            "Matrix Green",
            "Amber CRT",
        ]
    }

    pub fn by_name(name: &str) -> Self {
        match name {
            "Classic PuTTY" => Self {
                name: "Classic PuTTY",
                bg: Color32::from_rgb(0, 0, 0),
                fg: Color32::from_rgb(187, 187, 187),
                cursor: Color32::from_rgb(0, 255, 0),
                selection_bg: Color32::from_rgba_premultiplied(70, 110, 180, 120),
                ansi: [
                    Color32::from_rgb(0, 0, 0),
                    Color32::from_rgb(187, 0, 0),
                    Color32::from_rgb(0, 187, 0),
                    Color32::from_rgb(187, 187, 0),
                    Color32::from_rgb(0, 0, 187),
                    Color32::from_rgb(187, 0, 187),
                    Color32::from_rgb(0, 187, 187),
                    Color32::from_rgb(187, 187, 187),
                    Color32::from_rgb(85, 85, 85),
                    Color32::from_rgb(255, 85, 85),
                    Color32::from_rgb(85, 255, 85),
                    Color32::from_rgb(255, 255, 85),
                    Color32::from_rgb(85, 85, 255),
                    Color32::from_rgb(255, 85, 255),
                    Color32::from_rgb(85, 255, 255),
                    Color32::from_rgb(255, 255, 255),
                ],
            },
            "Dracula" => Self {
                name: "Dracula",
                bg: Color32::from_rgb(40, 42, 54),
                fg: Color32::from_rgb(248, 248, 242),
                cursor: Color32::from_rgb(255, 121, 198),
                selection_bg: Color32::from_rgba_premultiplied(68, 71, 90, 180),
                ansi: [
                    Color32::from_rgb(33, 34, 44),
                    Color32::from_rgb(255, 85, 85),
                    Color32::from_rgb(80, 250, 123),
                    Color32::from_rgb(241, 250, 140),
                    Color32::from_rgb(189, 147, 249),
                    Color32::from_rgb(255, 121, 198),
                    Color32::from_rgb(139, 233, 253),
                    Color32::from_rgb(248, 248, 242),
                    Color32::from_rgb(98, 114, 164),
                    Color32::from_rgb(255, 110, 110),
                    Color32::from_rgb(105, 255, 148),
                    Color32::from_rgb(255, 255, 165),
                    Color32::from_rgb(214, 172, 255),
                    Color32::from_rgb(255, 146, 223),
                    Color32::from_rgb(164, 255, 255),
                    Color32::from_rgb(255, 255, 255),
                ],
            },
            "Solarized Dark" => Self {
                name: "Solarized Dark",
                bg: Color32::from_rgb(0, 43, 54),
                fg: Color32::from_rgb(131, 148, 150),
                cursor: Color32::from_rgb(181, 137, 0),
                selection_bg: Color32::from_rgba_premultiplied(7, 54, 66, 200),
                ansi: [
                    Color32::from_rgb(7, 54, 66),
                    Color32::from_rgb(220, 50, 47),
                    Color32::from_rgb(133, 153, 0),
                    Color32::from_rgb(181, 137, 0),
                    Color32::from_rgb(38, 139, 210),
                    Color32::from_rgb(211, 54, 130),
                    Color32::from_rgb(42, 161, 152),
                    Color32::from_rgb(238, 232, 213),
                    Color32::from_rgb(0, 43, 54),
                    Color32::from_rgb(203, 75, 22),
                    Color32::from_rgb(88, 110, 117),
                    Color32::from_rgb(101, 123, 131),
                    Color32::from_rgb(131, 148, 150),
                    Color32::from_rgb(108, 113, 196),
                    Color32::from_rgb(147, 161, 161),
                    Color32::from_rgb(253, 246, 227),
                ],
            },
            "Nord" => Self {
                name: "Nord",
                bg: Color32::from_rgb(46, 52, 64),
                fg: Color32::from_rgb(216, 222, 233),
                cursor: Color32::from_rgb(136, 192, 208),
                selection_bg: Color32::from_rgba_premultiplied(67, 76, 94, 180),
                ansi: [
                    Color32::from_rgb(59, 66, 82),
                    Color32::from_rgb(191, 97, 106),
                    Color32::from_rgb(163, 190, 140),
                    Color32::from_rgb(235, 203, 139),
                    Color32::from_rgb(129, 161, 193),
                    Color32::from_rgb(180, 142, 173),
                    Color32::from_rgb(136, 192, 208),
                    Color32::from_rgb(229, 233, 240),
                    Color32::from_rgb(76, 86, 106),
                    Color32::from_rgb(191, 97, 106),
                    Color32::from_rgb(163, 190, 140),
                    Color32::from_rgb(235, 203, 139),
                    Color32::from_rgb(129, 161, 193),
                    Color32::from_rgb(180, 142, 173),
                    Color32::from_rgb(143, 188, 187),
                    Color32::from_rgb(236, 239, 244),
                ],
            },
            "Matrix Green" => Self {
                name: "Matrix Green",
                bg: Color32::from_rgb(6, 14, 8),
                fg: Color32::from_rgb(40, 240, 90),
                cursor: Color32::from_rgb(120, 255, 150),
                selection_bg: Color32::from_rgba_premultiplied(20, 90, 40, 160),
                ansi: [
                    Color32::from_rgb(6, 14, 8),
                    Color32::from_rgb(220, 60, 60),
                    Color32::from_rgb(40, 230, 90),
                    Color32::from_rgb(160, 240, 80),
                    Color32::from_rgb(30, 180, 120),
                    Color32::from_rgb(100, 220, 140),
                    Color32::from_rgb(60, 240, 180),
                    Color32::from_rgb(160, 250, 180),
                    Color32::from_rgb(20, 60, 30),
                    Color32::from_rgb(255, 90, 90),
                    Color32::from_rgb(80, 255, 120),
                    Color32::from_rgb(200, 255, 110),
                    Color32::from_rgb(70, 220, 160),
                    Color32::from_rgb(140, 255, 170),
                    Color32::from_rgb(100, 255, 210),
                    Color32::from_rgb(220, 255, 230),
                ],
            },
            "Amber CRT" => Self {
                name: "Amber CRT",
                bg: Color32::from_rgb(18, 12, 4),
                fg: Color32::from_rgb(255, 176, 0),
                cursor: Color32::from_rgb(255, 210, 80),
                selection_bg: Color32::from_rgba_premultiplied(110, 70, 0, 160),
                ansi: [
                    Color32::from_rgb(18, 12, 4),
                    Color32::from_rgb(255, 90, 40),
                    Color32::from_rgb(230, 160, 0),
                    Color32::from_rgb(255, 195, 40),
                    Color32::from_rgb(200, 135, 0),
                    Color32::from_rgb(245, 150, 50),
                    Color32::from_rgb(255, 185, 60),
                    Color32::from_rgb(255, 200, 100),
                    Color32::from_rgb(90, 60, 15),
                    Color32::from_rgb(255, 120, 70),
                    Color32::from_rgb(255, 185, 30),
                    Color32::from_rgb(255, 215, 90),
                    Color32::from_rgb(230, 165, 40),
                    Color32::from_rgb(255, 175, 90),
                    Color32::from_rgb(255, 210, 120),
                    Color32::from_rgb(255, 235, 180),
                ],
            },
            _ => Self {
                name: "Cuty Dark",
                bg: Color32::from_rgb(17, 21, 28),
                fg: Color32::from_rgb(220, 228, 240),
                cursor: Color32::from_rgb(88, 166, 255),
                selection_bg: Color32::from_rgba_premultiplied(56, 110, 190, 140),
                ansi: [
                    Color32::from_rgb(28, 33, 43),
                    Color32::from_rgb(244, 112, 103),
                    Color32::from_rgb(87, 171, 90),
                    Color32::from_rgb(198, 144, 38),
                    Color32::from_rgb(83, 155, 245),
                    Color32::from_rgb(176, 131, 240),
                    Color32::from_rgb(57, 197, 207),
                    Color32::from_rgb(201, 209, 217),
                    Color32::from_rgb(99, 110, 123),
                    Color32::from_rgb(255, 147, 138),
                    Color32::from_rgb(107, 196, 109),
                    Color32::from_rgb(218, 170, 63),
                    Color32::from_rgb(108, 182, 255),
                    Color32::from_rgb(208, 172, 255),
                    Color32::from_rgb(86, 212, 221),
                    Color32::from_rgb(240, 246, 252),
                ],
            },
        }
    }

    pub fn ansi_to_cell_color(&self, idx: u8) -> CellColor {
        if idx < 16 {
            let c = self.ansi[idx as usize];
            CellColor::rgb(c.r(), c.g(), c.b())
        } else if idx < 232 {
            let n = idx - 16;
            let r_idx = n / 36;
            let g_idx = (n % 36) / 6;
            let b_idx = n % 6;
            let to_val = |v: u8| if v == 0 { 0 } else { 55 + v * 40 };
            CellColor::rgb(to_val(r_idx), to_val(g_idx), to_val(b_idx))
        } else {
            let gray = 8 + (idx - 232) * 10;
            CellColor::rgb(gray, gray, gray)
        }
    }
}

#[derive(Debug, Clone)]
pub struct DetectedUrl {
    pub start_col: usize,
    pub end_col: usize,
    pub url: String,
}

pub struct TerminalEmulator {
    parser: Parser,
    pub state: TerminalState,
}

pub struct TerminalState {
    pub cols: usize,
    pub rows: usize,
    pub grid: Vec<Vec<TerminalCell>>,
    pub alt_grid: Vec<Vec<TerminalCell>>,
    pub using_alt_screen: bool,
    pub scrollback: VecDeque<Vec<TerminalCell>>,
    pub max_scrollback: usize,
    pub scroll_offset: usize,

    pub cursor_col: usize,
    pub cursor_row: usize,
    pub saved_cursor: (usize, usize),
    pub saved_alt_cursor: (usize, usize),
    pub cursor_visible: bool,

    pub scroll_top: usize,
    pub scroll_bottom: usize,

    pub cur_attr: TerminalCell,
    pub dec_line_drawing: bool,
    pub application_cursor_keys: bool,
    pub bracketed_paste: bool,
    pub dynamic_title: Option<String>,
    pub theme: TerminalTheme,

    // Mouse selection (absolute row in scrollback + grid, column)
    pub selection_start: Option<(usize, usize)>,
    pub selection_end: Option<(usize, usize)>,

    // Outbound response sequences generated by CSI/ESC queries (CPR \x1b[r;cR, DA, etc.)
    pub pending_responses: Vec<Vec<u8>>,
}

impl TerminalEmulator {
    pub fn new(cols: usize, rows: usize, max_scrollback: usize, theme_name: &str) -> Self {
        let cols = cols.max(10);
        let rows = rows.max(4);
        let grid = vec![vec![TerminalCell::default(); cols]; rows];
        let alt_grid = vec![vec![TerminalCell::default(); cols]; rows];
        Self {
            parser: Parser::new(),
            state: TerminalState {
                cols,
                rows,
                grid,
                alt_grid,
                using_alt_screen: false,
                scrollback: VecDeque::with_capacity(max_scrollback.min(20_000)),
                max_scrollback: max_scrollback.max(500),
                scroll_offset: 0,
                cursor_col: 0,
                cursor_row: 0,
                saved_cursor: (0, 0),
                saved_alt_cursor: (0, 0),
                cursor_visible: true,
                scroll_top: 0,
                scroll_bottom: rows.saturating_sub(1),
                cur_attr: TerminalCell::default(),
                dec_line_drawing: false,
                application_cursor_keys: false,
                bracketed_paste: false,
                dynamic_title: None,
                theme: TerminalTheme::by_name(theme_name),
                selection_start: None,
                selection_end: None,
                pending_responses: Vec::new(),
            },
        }
    }

    pub fn take_pending_responses(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.state.pending_responses)
    }

    pub fn feed_bytes(&mut self, bytes: &[u8]) {
        self.parser.advance(&mut self.state, bytes);
    }

    pub fn feed_str(&mut self, text: &str) {
        self.feed_bytes(text.as_bytes());
    }

    pub fn resize(&mut self, new_cols: usize, new_rows: usize) {
        self.state.resize(new_cols, new_rows);
    }

    pub fn clear_scrollback(&mut self) {
        self.state.scrollback.clear();
        self.state.scroll_offset = 0;
    }

    pub fn reset(&mut self) {
        let cols = self.state.cols;
        let rows = self.state.rows;
        let max_sb = self.state.max_scrollback;
        let theme_name = self.state.theme.name;
        *self = Self::new(cols, rows, max_sb, theme_name);
    }
}

impl TerminalState {
    pub fn resize(&mut self, new_cols: usize, new_rows: usize) {
        let new_cols = new_cols.max(20);
        let new_rows = new_rows.max(5);
        if new_cols == self.cols && new_rows == self.rows {
            return;
        }

        for row in &mut self.grid {
            row.resize(new_cols, TerminalCell::default());
        }
        self.grid
            .resize(new_rows, vec![TerminalCell::default(); new_cols]);

        for row in &mut self.alt_grid {
            row.resize(new_cols, TerminalCell::default());
        }
        self.alt_grid
            .resize(new_rows, vec![TerminalCell::default(); new_cols]);

        self.cols = new_cols;
        self.rows = new_rows;
        self.scroll_top = 0;
        self.scroll_bottom = new_rows.saturating_sub(1);
        self.cursor_col = self.cursor_col.min(new_cols.saturating_sub(1));
        self.cursor_row = self.cursor_row.min(new_rows.saturating_sub(1));
    }

    fn active_grid_mut(&mut self) -> &mut Vec<Vec<TerminalCell>> {
        if self.using_alt_screen {
            &mut self.alt_grid
        } else {
            &mut self.grid
        }
    }

    pub fn active_grid(&self) -> &Vec<Vec<TerminalCell>> {
        if self.using_alt_screen {
            &self.alt_grid
        } else {
            &self.grid
        }
    }

    pub fn total_lines(&self) -> usize {
        if self.using_alt_screen {
            self.rows
        } else {
            self.scrollback.len() + self.rows
        }
    }

    pub fn line_at_absolute(&self, abs_row: usize) -> Option<&Vec<TerminalCell>> {
        if self.using_alt_screen {
            self.alt_grid.get(abs_row)
        } else if abs_row < self.scrollback.len() {
            self.scrollback.get(abs_row)
        } else {
            self.grid.get(abs_row - self.scrollback.len())
        }
    }

    pub fn visible_start_abs_row(&self) -> usize {
        if self.using_alt_screen {
            0
        } else {
            self.scrollback.len().saturating_sub(self.scroll_offset)
        }
    }

    pub fn extract_selected_text(&self) -> Option<String> {
        let (s, e) = match (self.selection_start, self.selection_end) {
            (Some(s), Some(e)) => {
                if s <= e {
                    (s, e)
                } else {
                    (e, s)
                }
            }
            _ => return None,
        };
        if s == e {
            return None;
        }

        let mut out = String::new();
        for r in s.0..=e.0 {
            if let Some(row_cells) = self.line_at_absolute(r) {
                let c_start = if r == s.0 { s.1 } else { 0 };
                let c_end = if r == e.0 {
                    e.1.min(row_cells.len().saturating_sub(1))
                } else {
                    row_cells.len().saturating_sub(1)
                };
                if c_start <= c_end && c_start < row_cells.len() {
                    let slice = &row_cells[c_start..=c_end.min(row_cells.len() - 1)];
                    let line_str: String = slice.iter().map(|c| c.ch).collect();
                    out.push_str(line_str.trim_end());
                }
                if r < e.0 {
                    out.push('\n');
                }
            }
        }
        if out.is_empty() { None } else { Some(out) }
    }

    pub fn is_cell_selected(&self, abs_row: usize, col: usize) -> bool {
        let (s, e) = match (self.selection_start, self.selection_end) {
            (Some(s), Some(e)) => {
                if s <= e {
                    (s, e)
                } else {
                    (e, s)
                }
            }
            _ => return false,
        };
        if abs_row < s.0 || abs_row > e.0 {
            return false;
        }
        if s.0 == e.0 {
            return col >= s.1 && col <= e.1;
        }
        if abs_row == s.0 {
            col >= s.1
        } else if abs_row == e.0 {
            col <= e.1
        } else {
            true
        }
    }

    pub fn dump_all_text(&self) -> String {
        let mut out = String::new();
        for row in &self.scrollback {
            let line: String = row.iter().map(|c| c.ch).collect();
            out.push_str(line.trim_end());
            out.push('\n');
        }
        for row in self.active_grid() {
            let line: String = row.iter().map(|c| c.ch).collect();
            out.push_str(line.trim_end());
            out.push('\n');
        }
        out
    }

    pub fn detect_urls_in_row(&self, row_cells: &[TerminalCell]) -> Vec<DetectedUrl> {
        // Fast zero-allocation pre-check: skip String allocation when the row cannot contain "http://" or "https://"
        if !row_cells.iter().any(|c| c.ch == ':') {
            return Vec::new();
        }
        let line: String = row_cells.iter().map(|c| c.ch).collect();
        let mut urls = Vec::new();
        for prefix in ["https://", "http://"] {
            let mut search_from = 0;
            while let Some(pos) = line[search_from..].find(prefix) {
                let byte_start = search_from + pos;
                let rest = &line[byte_start..];
                let url_len = rest
                    .chars()
                    .take_while(|c| {
                        !c.is_whitespace()
                            && *c != '"'
                            && *c != '\''
                            && *c != '<'
                            && *c != '>'
                            && *c != ')'
                            && *c != ']'
                    })
                    .map(|c| c.len_utf8())
                    .sum::<usize>();
                let raw_url = rest[..url_len].trim_end_matches(['.', ',', ';', ':']);
                if raw_url.len() > prefix.len() + 3 {
                    let start_col = line[..byte_start].chars().count();
                    let char_len = raw_url.chars().count();
                    urls.push(DetectedUrl {
                        start_col,
                        end_col: start_col + char_len - 1,
                        url: raw_url.to_string(),
                    });
                }
                search_from = byte_start + url_len.max(prefix.len());
            }
        }
        urls
    }

    fn scroll_up_region(&mut self, top: usize, bottom: usize, count: usize) {
        let bottom = bottom.min(self.rows.saturating_sub(1));
        if top > bottom {
            return;
        }
        let cols = self.cols;
        for _ in 0..count {
            if !self.using_alt_screen && top == 0 {
                let removed = self.grid.remove(0);
                self.scrollback.push_back(removed);
                while self.scrollback.len() > self.max_scrollback {
                    self.scrollback.pop_front();
                }
                self.grid
                    .insert(bottom, vec![TerminalCell::default(); cols]);
            } else {
                let grid = self.active_grid_mut();
                grid.remove(top);
                grid.insert(bottom, vec![TerminalCell::default(); cols]);
            }
        }
    }

    fn scroll_down_region(&mut self, top: usize, bottom: usize, count: usize) {
        let bottom = bottom.min(self.rows.saturating_sub(1));
        if top > bottom {
            return;
        }
        let cols = self.cols;
        let grid = self.active_grid_mut();
        for _ in 0..count {
            grid.remove(bottom);
            grid.insert(top, vec![TerminalCell::default(); cols]);
        }
    }

    fn newline(&mut self) {
        if self.cursor_row >= self.scroll_bottom {
            let top = self.scroll_top;
            let bottom = self.scroll_bottom;
            self.scroll_up_region(top, bottom, 1);
        } else if self.cursor_row + 1 < self.rows {
            self.cursor_row += 1;
        }
    }

    fn put_char(&mut self, ch: char) {
        let mapped = if self.dec_line_drawing {
            map_dec_special(ch)
        } else {
            ch
        };

        if self.cursor_col >= self.cols {
            self.cursor_col = 0;
            self.newline();
        }

        let mut cell = self.cur_attr;
        cell.ch = mapped;

        let r = self.cursor_row.min(self.rows.saturating_sub(1));
        let c = self.cursor_col.min(self.cols.saturating_sub(1));
        self.active_grid_mut()[r][c] = cell;
        self.cursor_col += 1;
    }

    fn handle_sgr(&mut self, params: &Params) {
        let mut iter = params.iter();
        let mut any = false;
        while let Some(sub) = iter.next() {
            any = true;
            let code = sub.first().copied().unwrap_or(0);
            match code {
                0 => self.cur_attr = TerminalCell::default(),
                1 => self.cur_attr.set_flag(CELL_FLAG_BOLD, true),
                2 => self.cur_attr.set_flag(CELL_FLAG_DIM, true),
                3 => self.cur_attr.set_flag(CELL_FLAG_ITALIC, true),
                4 => self.cur_attr.set_flag(CELL_FLAG_UNDERLINE, true),
                7 => self.cur_attr.set_flag(CELL_FLAG_INVERSE, true),
                21 | 22 => {
                    self.cur_attr.set_flag(CELL_FLAG_BOLD, false);
                    self.cur_attr.set_flag(CELL_FLAG_DIM, false);
                }
                23 => self.cur_attr.set_flag(CELL_FLAG_ITALIC, false),
                24 => self.cur_attr.set_flag(CELL_FLAG_UNDERLINE, false),
                27 => self.cur_attr.set_flag(CELL_FLAG_INVERSE, false),
                30..=37 => {
                    let idx = (code - 30) as u8;
                    self.cur_attr.fg = self.theme.ansi_to_cell_color(idx);
                }
                39 => self.cur_attr.fg = CellColor::default_color(),
                40..=47 => {
                    let idx = (code - 40) as u8;
                    self.cur_attr.bg = self.theme.ansi_to_cell_color(idx);
                }
                49 => self.cur_attr.bg = CellColor::default_color(),
                90..=97 => {
                    let idx = (code - 90 + 8) as u8;
                    self.cur_attr.fg = self.theme.ansi_to_cell_color(idx);
                }
                100..=107 => {
                    let idx = (code - 100 + 8) as u8;
                    self.cur_attr.bg = self.theme.ansi_to_cell_color(idx);
                }
                38 | 48 => {
                    let is_fg = code == 38;
                    if sub.len() >= 3 && sub[1] == 5 {
                        let c = self.theme.ansi_to_cell_color(sub[2] as u8);
                        if is_fg {
                            self.cur_attr.fg = c;
                        } else {
                            self.cur_attr.bg = c;
                        }
                    } else if sub.len() >= 5 && sub[1] == 2 {
                        let c = CellColor::rgb(sub[2] as u8, sub[3] as u8, sub[4] as u8);
                        if is_fg {
                            self.cur_attr.fg = c;
                        } else {
                            self.cur_attr.bg = c;
                        }
                    } else if let Some(mode_sub) = iter.next() {
                        let mode = mode_sub.first().copied().unwrap_or(0);
                        if mode == 5 {
                            if let Some(idx_sub) = iter.next() {
                                let idx = idx_sub.first().copied().unwrap_or(0) as u8;
                                let c = self.theme.ansi_to_cell_color(idx);
                                if is_fg {
                                    self.cur_attr.fg = c;
                                } else {
                                    self.cur_attr.bg = c;
                                }
                            }
                        } else if mode == 2 {
                            let r = iter.next().and_then(|s| s.first().copied()).unwrap_or(0) as u8;
                            let g = iter.next().and_then(|s| s.first().copied()).unwrap_or(0) as u8;
                            let b = iter.next().and_then(|s| s.first().copied()).unwrap_or(0) as u8;
                            let c = CellColor::rgb(r, g, b);
                            if is_fg {
                                self.cur_attr.fg = c;
                            } else {
                                self.cur_attr.bg = c;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        if !any {
            self.cur_attr = TerminalCell::default();
        }
    }
}

impl Perform for TerminalState {
    fn print(&mut self, c: char) {
        self.put_char(c);
    }

    fn execute(&mut self, byte: u8) {
        match byte {
            0x08 => {
                // Backspace
                self.cursor_col = self.cursor_col.saturating_sub(1);
            }
            0x09 => {
                // Tab
                let next_tab = ((self.cursor_col / 8) + 1) * 8;
                self.cursor_col = next_tab.min(self.cols.saturating_sub(1));
            }
            0x0A..=0x0C => {
                // LF, VT, FF
                self.newline();
            }
            0x0D => {
                // CR
                self.cursor_col = 0;
            }
            0x0E => {
                self.dec_line_drawing = true;
            }
            0x0F => {
                self.dec_line_drawing = false;
            }
            _ => {}
        }
    }

    fn csi_dispatch(&mut self, params: &Params, intermediates: &[u8], _ignore: bool, action: char) {
        let p0 = params
            .iter()
            .next()
            .and_then(|s| s.first().copied())
            .unwrap_or(0) as usize;
        let p1 = params
            .iter()
            .nth(1)
            .and_then(|s| s.first().copied())
            .unwrap_or(0) as usize;
        let is_private = intermediates.contains(&b'?');

        match action {
            'A' => {
                let n = p0.max(1);
                self.cursor_row = self.cursor_row.saturating_sub(n);
            }
            'B' => {
                let n = p0.max(1);
                self.cursor_row = (self.cursor_row + n).min(self.rows.saturating_sub(1));
            }
            'C' => {
                let n = p0.max(1);
                self.cursor_col = (self.cursor_col + n).min(self.cols.saturating_sub(1));
            }
            'D' => {
                let n = p0.max(1);
                self.cursor_col = self.cursor_col.saturating_sub(n);
            }
            'E' => {
                let n = p0.max(1);
                self.cursor_row = (self.cursor_row + n).min(self.rows.saturating_sub(1));
                self.cursor_col = 0;
            }
            'F' => {
                let n = p0.max(1);
                self.cursor_row = self.cursor_row.saturating_sub(n);
                self.cursor_col = 0;
            }
            'G' | '`' => {
                let col = p0.max(1) - 1;
                self.cursor_col = col.min(self.cols.saturating_sub(1));
            }
            'd' => {
                let row = p0.max(1) - 1;
                self.cursor_row = row.min(self.rows.saturating_sub(1));
            }
            'H' | 'f' => {
                let row = p0.max(1) - 1;
                let col = p1.max(1) - 1;
                self.cursor_row = row.min(self.rows.saturating_sub(1));
                self.cursor_col = col.min(self.cols.saturating_sub(1));
            }
            'J' => {
                let rows = self.rows;
                let cols = self.cols;
                let cr = self.cursor_row.min(rows.saturating_sub(1));
                let cc = self.cursor_col.min(cols.saturating_sub(1));
                let blank = TerminalCell {
                    bg: self.cur_attr.bg,
                    ..Default::default()
                };
                let grid = self.active_grid_mut();
                match p0 {
                    0 => {
                        grid[cr][cc..cols].fill(blank);
                        for row in grid.iter_mut().take(rows).skip(cr + 1) {
                            row[..cols].fill(blank);
                        }
                    }
                    1 => {
                        for row in grid.iter_mut().take(cr) {
                            row[..cols].fill(blank);
                        }
                        grid[cr][..=cc].fill(blank);
                    }
                    2 | 3 => {
                        for row in grid.iter_mut().take(rows) {
                            row[..cols].fill(blank);
                        }
                    }
                    _ => {}
                }
            }
            'K' => {
                let cols = self.cols;
                let cr = self.cursor_row.min(self.rows.saturating_sub(1));
                let cc = self.cursor_col.min(cols.saturating_sub(1));
                let blank = TerminalCell {
                    bg: self.cur_attr.bg,
                    ..Default::default()
                };
                let grid = self.active_grid_mut();
                match p0 {
                    0 => {
                        grid[cr][cc..cols].fill(blank);
                    }
                    1 => {
                        grid[cr][..=cc].fill(blank);
                    }
                    2 => {
                        grid[cr][..cols].fill(blank);
                    }
                    _ => {}
                }
            }
            'L' => {
                let n = p0.max(1);
                let cr = self.cursor_row;
                let bottom = self.scroll_bottom;
                self.scroll_down_region(cr, bottom, n);
            }
            'M' => {
                let n = p0.max(1);
                let cr = self.cursor_row;
                let bottom = self.scroll_bottom;
                self.scroll_up_region(cr, bottom, n);
            }
            'P' => {
                let n = p0.max(1);
                let cr = self.cursor_row.min(self.rows.saturating_sub(1));
                let cc = self.cursor_col.min(self.cols.saturating_sub(1));
                let cols = self.cols;
                let row = &mut self.active_grid_mut()[cr];
                for _ in 0..n.min(cols - cc) {
                    row.remove(cc);
                    row.push(TerminalCell::default());
                }
            }
            '@' => {
                let n = p0.max(1);
                let cr = self.cursor_row.min(self.rows.saturating_sub(1));
                let cc = self.cursor_col.min(self.cols.saturating_sub(1));
                let cols = self.cols;
                let row = &mut self.active_grid_mut()[cr];
                for _ in 0..n.min(cols - cc) {
                    row.insert(cc, TerminalCell::default());
                    row.pop();
                }
            }
            'X' => {
                let n = p0.max(1);
                let cr = self.cursor_row.min(self.rows.saturating_sub(1));
                let cc = self.cursor_col.min(self.cols.saturating_sub(1));
                let cols = self.cols;
                let row = &mut self.active_grid_mut()[cr];
                let end = (cc + n).min(cols);
                row[cc..end].fill(TerminalCell::default());
            }
            'S' => {
                let n = p0.max(1);
                let top = self.scroll_top;
                let bottom = self.scroll_bottom;
                self.scroll_up_region(top, bottom, n);
            }
            'T' => {
                let n = p0.max(1);
                let top = self.scroll_top;
                let bottom = self.scroll_bottom;
                self.scroll_down_region(top, bottom, n);
            }
            'r' => {
                let top = if p0 == 0 { 0 } else { p0 - 1 };
                let bottom = if p1 == 0 {
                    self.rows.saturating_sub(1)
                } else {
                    (p1 - 1).min(self.rows.saturating_sub(1))
                };
                if top < bottom {
                    self.scroll_top = top;
                    self.scroll_bottom = bottom;
                    self.cursor_row = 0;
                    self.cursor_col = 0;
                }
            }
            'm' => {
                self.handle_sgr(params);
            }
            's' => {
                self.saved_cursor = (self.cursor_col, self.cursor_row);
            }
            'u' => {
                self.cursor_col = self.saved_cursor.0.min(self.cols.saturating_sub(1));
                self.cursor_row = self.saved_cursor.1.min(self.rows.saturating_sub(1));
            }
            'h' if is_private => {
                for sub in params.iter() {
                    if let Some(&code) = sub.first() {
                        match code {
                            1 => self.application_cursor_keys = true,
                            25 => self.cursor_visible = true,
                            47 | 1047 | 1049 => {
                                if !self.using_alt_screen {
                                    self.saved_alt_cursor = (self.cursor_col, self.cursor_row);
                                    self.using_alt_screen = true;
                                    self.alt_grid =
                                        vec![vec![TerminalCell::default(); self.cols]; self.rows];
                                    self.cursor_col = 0;
                                    self.cursor_row = 0;
                                }
                            }
                            2004 => self.bracketed_paste = true,
                            _ => {}
                        }
                    }
                }
            }
            'l' if is_private => {
                for sub in params.iter() {
                    if let Some(&code) = sub.first() {
                        match code {
                            1 => self.application_cursor_keys = false,
                            25 => self.cursor_visible = false,
                            47 | 1047 | 1049 => {
                                if self.using_alt_screen {
                                    self.using_alt_screen = false;
                                    self.cursor_col =
                                        self.saved_alt_cursor.0.min(self.cols.saturating_sub(1));
                                    self.cursor_row =
                                        self.saved_alt_cursor.1.min(self.rows.saturating_sub(1));
                                }
                            }
                            2004 => self.bracketed_paste = false,
                            _ => {}
                        }
                    }
                }
            }
            'n' => {
                // Device Status Report (DSR)
                match p0 {
                    6 => {
                        // Cursor Position Report (CPR): 1-based row and col
                        let r = (self.cursor_row + 1).min(self.rows);
                        let c = (self.cursor_col + 1).min(self.cols);
                        let resp = format!("\x1b[{};{}R", r, c).into_bytes();
                        self.pending_responses.push(resp);
                    }
                    5 => {
                        // Operating status: 0 = OK (ready, no malfunction)
                        self.pending_responses.push(b"\x1b[0n".to_vec());
                    }
                    _ => {}
                }
            }
            'c' => {
                // Device Attributes (DA)
                if intermediates.is_empty() || intermediates == b"?" {
                    // Primary Device Attributes: report VT100 with Advanced Video Option
                    self.pending_responses.push(b"\x1b[?1;2c".to_vec());
                } else if intermediates == b">" {
                    // Secondary Device Attributes (DA2): terminal type 0, firmware 10, ROM 0
                    self.pending_responses.push(b"\x1b[>0;10;0c".to_vec());
                }
            }
            't' if p0 == 18 => {
                // Window manipulation: Report terminal size in characters: CSI 8 ; rows ; cols t
                let resp = format!("\x1b[8;{};{}t", self.rows, self.cols).into_bytes();
                self.pending_responses.push(resp);
            }
            _ => {}
        }
    }

    fn esc_dispatch(&mut self, intermediates: &[u8], _ignore: bool, byte: u8) {
        match (intermediates, byte) {
            (b"(", b'0') => self.dec_line_drawing = true,
            (b"(", b'B') => self.dec_line_drawing = false,
            ([], b'7') => self.saved_cursor = (self.cursor_col, self.cursor_row),
            ([], b'8') => {
                self.cursor_col = self.saved_cursor.0.min(self.cols.saturating_sub(1));
                self.cursor_row = self.saved_cursor.1.min(self.rows.saturating_sub(1));
            }
            ([], b'D') => self.newline(),
            ([], b'M') => {
                if self.cursor_row <= self.scroll_top {
                    let top = self.scroll_top;
                    let bottom = self.scroll_bottom;
                    self.scroll_down_region(top, bottom, 1);
                } else {
                    self.cursor_row = self.cursor_row.saturating_sub(1);
                }
            }
            ([], b'c') => {
                self.grid = vec![vec![TerminalCell::default(); self.cols]; self.rows];
                self.cursor_col = 0;
                self.cursor_row = 0;
                self.cur_attr = TerminalCell::default();
            }
            ([], b'Z') => {
                // Obsolete VT100 identification query (DECID)
                self.pending_responses.push(b"\x1b[?1;2c".to_vec());
            }
            _ => {}
        }
    }

    fn osc_dispatch(&mut self, params: &[&[u8]], _bell_terminated: bool) {
        if params.len() >= 2 {
            let cmd = params[0];
            if cmd == b"0" || cmd == b"2" {
                let title = String::from_utf8_lossy(params[1]).to_string();
                if !title.is_empty() {
                    self.dynamic_title = Some(title);
                }
            }
        }
    }
}

fn map_dec_special(c: char) -> char {
    match c {
        'j' => '┘',
        'k' => '┐',
        'l' => '┌',
        'm' => '└',
        'n' => '┼',
        'q' => '─',
        't' => '├',
        'u' => '┤',
        'v' => '┴',
        'w' => '┬',
        'x' => '│',
        'a' => '▒',
        '`' => '◆',
        _ => c,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cursor_position_report() {
        let mut term = TerminalEmulator::new(80, 24, 1000, "Cuty Dark");
        term.feed_bytes(b"\x1b[6n");
        let responses = term.take_pending_responses();
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0], b"\x1b[1;1R");

        // Move cursor to row 5, col 10 (1-indexed)
        term.feed_bytes(b"\x1b[5;10H");
        term.feed_bytes(b"\x1b[6n");
        let responses = term.take_pending_responses();
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0], b"\x1b[5;10R");
    }

    #[test]
    fn test_device_status_and_attributes() {
        let mut term = TerminalEmulator::new(80, 24, 1000, "Cuty Dark");
        term.feed_bytes(b"\x1b[5n");
        let responses = term.take_pending_responses();
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0], b"\x1b[0n");

        term.feed_bytes(b"\x1b[c");
        let responses = term.take_pending_responses();
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0], b"\x1b[?1;2c");

        term.feed_bytes(b"\x1b[18t");
        let responses = term.take_pending_responses();
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0], b"\x1b[8;24;80t");
    }
}
