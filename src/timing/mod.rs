use std::io::IsTerminal;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::core::{self, Printer, Sequence};

#[derive(Clone, Copy, Debug, Default)]
pub struct AttemptTiming {
    start: Option<Instant>,
    response_headers: Option<Duration>,
    dns: Option<Duration>,
    connect: Option<Duration>,
}

impl AttemptTiming {
    pub fn start() -> Self {
        Self {
            start: Some(Instant::now()),
            response_headers: None,
            dns: None,
            connect: None,
        }
    }

    pub fn mark_response_headers(&mut self) {
        if let Some(start) = self.start {
            self.response_headers = Some(start.elapsed());
        }
    }

    pub fn response_headers(self) -> Option<Duration> {
        self.response_headers
    }

    pub fn set_dns(&mut self, duration: Option<Duration>) {
        self.dns = duration;
    }

    pub fn set_connect(&mut self, duration: Option<Duration>) {
        self.connect = duration;
    }

    pub fn response_timing(self) -> Option<ResponseTiming> {
        let response_headers = self.response_headers?;
        Some(ResponseTiming {
            dns: self.dns,
            connect: self.connect,
            ttfb: response_headers.saturating_sub(self.connect.unwrap_or_default()),
            body: None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Phase {
    label: &'static str,
    color: Sequence,
    duration: Duration,
}

#[derive(Clone, Copy, Debug)]
pub struct ResponseTiming {
    pub dns: Option<Duration>,
    pub connect: Option<Duration>,
    pub ttfb: Duration,
    pub body: Option<Duration>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsTiming {
    pub host: String,
    pub addrs: Vec<IpAddr>,
    pub duration: Duration,
}

pub fn render_waterfall(timing: ResponseTiming, use_color: bool) -> String {
    let phases = build_phases(timing);
    if phases.is_empty() {
        return String::new();
    }

    let mut total = phases
        .iter()
        .fold(Duration::ZERO, |total, phase| total + phase.duration);
    let mut max_duration_width = phases
        .iter()
        .map(|phase| format_timing_duration(phase.duration).len())
        .max()
        .unwrap_or(0);
    let total_duration = format_timing_duration(total);
    max_duration_width = max_duration_width.max(total_duration.len());

    if total.is_zero() {
        total = Duration::from_nanos(1);
    }

    let bar_width = 60;
    let label_width = phases
        .iter()
        .map(|phase| phase.label.len())
        .chain(std::iter::once("Total".len()))
        .max()
        .unwrap_or(5);
    let mut out = Printer::new(use_color);
    out.push('\n');

    let mut offset = Duration::ZERO;
    let mut next_start = 0_usize;
    for phase in phases {
        let start_col = next_start;
        let end_nanos = (offset + phase.duration).as_nanos();
        let total_nanos = total.as_nanos().max(1);
        let mut end_col = ((end_nanos * bar_width as u128) / total_nanos) as usize;
        offset += phase.duration;
        if end_col <= start_col {
            end_col = start_col + 1;
        }
        if end_col > bar_width {
            end_col = bar_width;
        }
        next_start = end_col;

        out.write_info_prefix();
        out.write_styled(
            &pad_label(phase.label, label_width),
            &[Sequence::Bold, phase.color],
        );
        out.push_str("  ");
        for column in 0..bar_width {
            if column >= start_col && column < end_col {
                out.write_styled("█", &[phase.color]);
            } else {
                out.write_styled("░", &[Sequence::Dim]);
            }
        }
        out.push_str("  ");
        out.write_styled(
            &pad_duration(&format_timing_duration(phase.duration), max_duration_width),
            &[Sequence::Dim],
        );
        out.push('\n');
    }

    out.write_info_prefix();
    let mut total_line = String::new();
    total_line.push_str(&pad_label("Total", label_width));
    total_line.push_str("  ");
    total_line.push_str(&"─".repeat(bar_width));
    total_line.push_str("  ");
    total_line.push_str(&pad_duration(&total_duration, max_duration_width));
    total_line.push('\n');
    out.write_styled(&total_line, &[Sequence::Dim]);
    out.into_string()
        .expect("timing waterfall output is valid UTF-8")
}

pub fn render_dns_debug(dns: &DnsTiming, use_color: bool) -> String {
    let mut out = Printer::new(use_color);
    out.write_info_prefix();
    out.write_styled("DNS", &[Sequence::Bold, Sequence::Yellow]);
    out.push_str(": ");
    out.push_str(&dns.host);
    out.push_str(" ");
    out.write_styled(
        &format!("({})", format_timing_duration(dns.duration)),
        &[Sequence::Dim],
    );
    out.push('\n');
    for addr in &dns.addrs {
        out.write_info_prefix();
        out.push_str("  ");
        out.write_styled(&addr.to_string(), &[Sequence::Italic]);
        out.push('\n');
    }
    out.into_string()
        .expect("timing debug output is valid UTF-8")
}

pub fn print_debug_lines(timing: &AttemptTiming, target: &str, color: Option<&str>) {
    let connect_elapsed = timing
        .connect
        .or(timing.response_headers)
        .unwrap_or_default();
    let ttfb_elapsed = timing
        .response_headers
        .map(|elapsed| elapsed.saturating_sub(timing.connect.unwrap_or_default()))
        .unwrap_or_default();
    let mut out = Printer::new(core::color_enabled(color, std::io::stderr().is_terminal()));
    out.write_info_prefix();
    out.write_styled("Connect", &[Sequence::Bold, Sequence::Yellow]);
    out.push_str(": ");
    out.push_str(target);
    out.push_str(" ");
    out.write_styled(
        &format!("({})", format_timing_duration(connect_elapsed)),
        &[Sequence::Dim],
    );
    out.push('\n');
    out.write_info_prefix();
    out.write_styled("TTFB", &[Sequence::Bold, Sequence::Yellow]);
    out.push_str(": ");
    out.push_str(&format_timing_duration(ttfb_elapsed));
    out.push('\n');
    out.write_info_prefix();
    out.push('\n');
    let mut stderr = std::io::stderr();
    let _ = out.flush_to(&mut stderr);
}

fn build_phases(timing: ResponseTiming) -> Vec<Phase> {
    let mut phases = Vec::new();
    if let Some(dns) = timing.dns {
        phases.push(Phase {
            label: "DNS",
            color: Sequence::Cyan,
            duration: dns,
        });
    }
    if let Some(connect) = timing.connect {
        phases.push(Phase {
            label: "Connect",
            color: Sequence::Green,
            duration: connect,
        });
    }
    phases.push(Phase {
        label: "TTFB",
        color: Sequence::Magenta,
        duration: timing.ttfb,
    });
    if let Some(body) = timing.body {
        phases.push(Phase {
            label: "Body",
            color: Sequence::Blue,
            duration: body,
        });
    }
    phases
}

fn pad_label(label: &str, width: usize) -> String {
    format!("{label:<width$}")
}

fn pad_duration(duration: &str, width: usize) -> String {
    format!("{duration:>width$}")
}

pub fn format_timing_duration(duration: Duration) -> String {
    if duration < Duration::from_secs(1) {
        format!("{:.1} ms", duration.as_micros() as f64 / 1000.0)
    } else {
        format!("{:.2} s", duration.as_secs_f64())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_timing_duration_matches_go_units() {
        assert_eq!(format_timing_duration(Duration::from_micros(500)), "0.5 ms");
        assert_eq!(format_timing_duration(Duration::from_millis(12)), "12.0 ms");
        assert_eq!(
            format_timing_duration(Duration::from_millis(1500)),
            "1.50 s"
        );
    }

    #[test]
    fn render_waterfall_contains_labels_and_bar_glyphs() {
        let out = render_waterfall(
            ResponseTiming {
                dns: None,
                connect: None,
                ttfb: Duration::from_millis(7),
                body: Some(Duration::from_millis(3)),
            },
            false,
        );

        assert!(out.contains("TTFB"));
        assert!(out.contains("Body"));
        assert!(out.contains("Total"));
        assert!(out.contains('█'));
        assert!(out.contains('─'));
    }

    #[test]
    fn render_waterfall_omits_body_when_unread() {
        let out = render_waterfall(
            ResponseTiming {
                dns: None,
                connect: None,
                ttfb: Duration::ZERO,
                body: None,
            },
            false,
        );

        assert!(out.contains("TTFB"));
        assert!(out.contains("Total"));
        assert!(!out.contains("Body"));
    }

    #[test]
    fn render_waterfall_handles_zero_duration() {
        let out = render_waterfall(
            ResponseTiming {
                dns: None,
                connect: None,
                ttfb: Duration::ZERO,
                body: None,
            },
            false,
        );

        assert!(out.contains("TTFB"));
        assert!(out.contains('█'));
    }

    #[test]
    fn render_debug_dns_uses_go_styles() {
        let out = render_dns_debug(
            &DnsTiming {
                host: "localhost".to_string(),
                addrs: vec![
                    IpAddr::from([127, 0, 0, 1]),
                    IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]),
                ],
                duration: Duration::from_micros(500),
            },
            true,
        );

        assert!(out.contains("\x1b[1m\x1b[33mDNS\x1b[0m: localhost"));
        assert!(out.contains("\x1b[3m127.0.0.1\x1b[0m"));
        assert!(out.contains("\x1b[3m::1\x1b[0m"));
    }

    #[test]
    fn render_waterfall_colors_phase_labels_and_bars() {
        let out = render_waterfall(
            ResponseTiming {
                dns: Some(Duration::from_millis(2)),
                connect: Some(Duration::from_millis(5)),
                ttfb: Duration::from_millis(7),
                body: Some(Duration::from_millis(3)),
            },
            true,
        );

        assert!(out.contains("\x1b[1m\x1b[36mDNS  "));
        assert!(out.contains("\x1b[1m\x1b[32mConnect"));
        assert!(out.contains("\x1b[1m\x1b[35mTTFB "));
        assert!(out.contains("\x1b[34m█\x1b[0m"));
        assert!(out.contains("\x1b[2mTotal"));
    }

    #[test]
    fn render_waterfall_aligns_labels_wider_than_total() {
        let out = render_waterfall(
            ResponseTiming {
                dns: Some(Duration::from_millis(2)),
                connect: Some(Duration::from_millis(5)),
                ttfb: Duration::from_millis(7),
                body: None,
            },
            false,
        );

        for line in out.lines().filter(|line| line.contains('█')) {
            let bar_start = line
                .char_indices()
                .find_map(|(index, ch)| (ch == '█' || ch == '░').then_some(index))
                .expect("waterfall line has a bar");
            assert_eq!(bar_start, 11, "{line}");
        }
    }

    #[test]
    fn response_timing_subtracts_connect_from_ttfb() {
        let mut timing = AttemptTiming::start();
        timing.response_headers = Some(Duration::from_millis(25));
        timing.set_dns(Some(Duration::from_millis(3)));
        timing.set_connect(Some(Duration::from_millis(10)));

        let response = timing.response_timing().unwrap();

        assert_eq!(response.dns, Some(Duration::from_millis(3)));
        assert_eq!(response.connect, Some(Duration::from_millis(10)));
        assert_eq!(response.ttfb, Duration::from_millis(15));
    }
}
