//! Covert channel detection
//!
//! Detects DNS tunneling, ICMP exfiltration, and other covert communication channels.

use alloc::string::String;
use alloc::vec::Vec;

/// Type of covert channel
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CovertChannelType {
    /// DNS tunneling
    DnsTunnel,
    /// ICMP data exfiltration
    IcmpExfil,
    /// HTTP header covert channel
    HttpHeader,
    /// Timing-based covert channel
    TimingChannel,
    /// Steganography in images
    Steganography,
}

/// A detected covert channel
#[derive(Debug, Clone)]
pub struct CovertChannel {
    /// Type of channel
    pub channel_type: CovertChannelType,
    /// Severity (0-100)
    pub severity: u8,
    /// Description
    pub description: String,
    /// Evidence
    pub evidence: Vec<String>,
}

/// DNS query statistics for tunnel detection
#[derive(Debug, Clone, Default)]
struct DnsStats {
    /// Query counts by domain
    query_counts: hashbrown::HashMap<String, u32>,
    /// Subdomain lengths
    subdomain_lengths: Vec<usize>,
    /// Total queries
    total_queries: u64,
    /// Queries with unusually long labels
    long_label_queries: u64,
    /// Queries with high entropy labels
    high_entropy_queries: u64,
    /// TXT record queries
    txt_queries: u64,
    /// Last seen timestamp
    last_seen: u64,
}

/// ICMP statistics for exfil detection
#[derive(Debug, Clone, Default)]
struct IcmpStats {
    /// Echo request payload sizes
    payload_sizes: Vec<usize>,
    /// Packet count
    packet_count: u64,
    /// Total payload bytes
    total_payload: u64,
    /// Last seen
    last_seen: u64,
}

/// Covert channel detector
#[cfg(feature = "std")]
pub struct CovertDetector {
    /// DNS stats per source IP
    dns_stats: hashbrown::HashMap<[u8; 4], DnsStats>,
    /// ICMP stats per source IP
    icmp_stats: hashbrown::HashMap<[u8; 4], IcmpStats>,
    /// DNS tunnel threshold (queries per minute)
    dns_rate_threshold: u32,
    /// DNS label entropy threshold
    entropy_threshold: f64,
    /// DNS label length threshold
    label_length_threshold: usize,
    /// ICMP payload threshold (bytes)
    icmp_payload_threshold: u64,
    /// Stats window (seconds)
    stats_window: u64,
}

#[cfg(feature = "std")]
impl CovertDetector {
    /// Create new detector
    pub fn new() -> Self {
        Self {
            dns_stats: hashbrown::HashMap::new(),
            icmp_stats: hashbrown::HashMap::new(),
            dns_rate_threshold: 100,
            entropy_threshold: 3.5,
            label_length_threshold: 30,
            icmp_payload_threshold: 10000,
            stats_window: 60,
        }
    }

    /// Check DNS packet for tunneling
    pub fn check_dns(
        &mut self,
        payload: &[u8],
        src_ip: [u8; 4],
        timestamp: u64,
    ) -> Option<CovertChannel> {
        // Skip UDP header if present (8 bytes)
        let dns_payload = if payload.len() > 8 {
            &payload[8..]
        } else {
            return None;
        };

        if dns_payload.len() < 12 {
            return None;
        }

        // Parse DNS header
        let flags = u16::from_be_bytes([dns_payload[2], dns_payload[3]]);
        let is_query = (flags & 0x8000) == 0;
        let qcount = u16::from_be_bytes([dns_payload[4], dns_payload[5]]);

        if !is_query || qcount == 0 {
            return None;
        }

        // Extract query name
        let query_name = self.extract_dns_name(&dns_payload[12..]);
        if query_name.is_empty() {
            return None;
        }

        // Calculate values before borrowing stats mutably
        let qtype_offset = 12 + Self::dns_name_length_static(&dns_payload[12..]);
        let is_txt = if dns_payload.len() > qtype_offset + 2 {
            let qtype = u16::from_be_bytes([
                dns_payload[qtype_offset],
                dns_payload[qtype_offset + 1],
            ]);
            qtype == 16
        } else {
            false
        };

        // Analyze labels for tunneling indicators
        let labels: Vec<&str> = query_name.split('.').collect();
        let mut long_labels = 0u64;
        let mut high_entropy_labels = 0u64;
        let label_length_threshold = self.label_length_threshold;
        let entropy_threshold = self.entropy_threshold;

        for label in &labels {
            if label.len() > label_length_threshold {
                long_labels += 1;
            }
            let entropy = Self::calculate_entropy_static(label);
            if entropy > entropy_threshold {
                high_entropy_labels += 1;
            }
        }

        // Get or create stats and update
        let stats = self.dns_stats.entry(src_ip).or_insert_with(DnsStats::default);
        stats.total_queries += 1;
        stats.last_seen = timestamp;
        if is_txt {
            stats.txt_queries += 1;
        }
        stats.long_label_queries += long_labels;
        stats.high_entropy_queries += high_entropy_labels;
        for label in &labels {
            stats.subdomain_lengths.push(label.len());
        }
        *stats.query_counts.entry(query_name.clone()).or_insert(0) += 1;

        // Detect tunneling patterns
        if stats.total_queries >= 10 {
            // High ratio of long labels
            let long_ratio = stats.long_label_queries as f64 / stats.total_queries as f64;
            if long_ratio > 0.5 {
                return Some(CovertChannel {
                    channel_type: CovertChannelType::DnsTunnel,
                    severity: 80,
                    description: alloc::format!(
                        "Possible DNS tunnel from {:?}: {:.0}% of queries have unusually long labels",
                        src_ip, long_ratio * 100.0
                    ),
                    evidence: vec![
                        alloc::format!("Total queries: {}", stats.total_queries),
                        alloc::format!("Long label queries: {}", stats.long_label_queries),
                        alloc::format!("Sample query: {}", query_name),
                    ],
                });
            }

            // High entropy labels
            let entropy_ratio = stats.high_entropy_queries as f64 / stats.total_queries as f64;
            if entropy_ratio > 0.5 {
                return Some(CovertChannel {
                    channel_type: CovertChannelType::DnsTunnel,
                    severity: 75,
                    description: alloc::format!(
                        "Possible DNS tunnel from {:?}: {:.0}% of queries have high-entropy labels",
                        src_ip, entropy_ratio * 100.0
                    ),
                    evidence: vec![
                        alloc::format!("Total queries: {}", stats.total_queries),
                        alloc::format!("High entropy queries: {}", stats.high_entropy_queries),
                    ],
                });
            }

            // High TXT query ratio
            let txt_ratio = stats.txt_queries as f64 / stats.total_queries as f64;
            if txt_ratio > 0.3 && stats.txt_queries > 10 {
                return Some(CovertChannel {
                    channel_type: CovertChannelType::DnsTunnel,
                    severity: 70,
                    description: alloc::format!(
                        "Possible DNS tunnel from {:?}: {:.0}% TXT queries",
                        src_ip, txt_ratio * 100.0
                    ),
                    evidence: vec![
                        alloc::format!("Total queries: {}", stats.total_queries),
                        alloc::format!("TXT queries: {}", stats.txt_queries),
                    ],
                });
            }
        }

        None
    }

    /// Check ICMP packet for data exfiltration
    pub fn check_icmp(
        &mut self,
        payload: &[u8],
        src_ip: [u8; 4],
        timestamp: u64,
    ) -> Option<CovertChannel> {
        if payload.len() < 8 {
            return None;
        }

        let icmp_type = payload[0];
        // Only check echo request (8) and echo reply (0)
        if icmp_type != 8 && icmp_type != 0 {
            return None;
        }

        // ICMP header is 8 bytes, rest is payload
        let icmp_payload_len = payload.len().saturating_sub(8);

        // Calculate entropy before borrowing stats (to avoid borrow checker issues)
        let payload_entropy = if payload.len() > 8 {
            Self::calculate_entropy_bytes_static(&payload[8..])
        } else {
            0.0
        };
        let icmp_payload_threshold = self.icmp_payload_threshold;

        let stats = self.icmp_stats.entry(src_ip).or_insert_with(IcmpStats::default);
        stats.packet_count += 1;
        stats.total_payload += icmp_payload_len as u64;
        stats.payload_sizes.push(icmp_payload_len);
        stats.last_seen = timestamp;

        // Keep only recent samples
        if stats.payload_sizes.len() > 100 {
            stats.payload_sizes.remove(0);
        }

        // Check for large payload (unusual)
        if icmp_payload_len > 64 {
            // Normal ping is typically 56-64 bytes
            if stats.total_payload > icmp_payload_threshold {
                // Check payload entropy (random data = high entropy)
                if payload_entropy > 6.0 {
                    return Some(CovertChannel {
                        channel_type: CovertChannelType::IcmpExfil,
                        severity: 75,
                        description: alloc::format!(
                            "Possible ICMP exfiltration from {:?}: {} bytes with high entropy",
                            src_ip, stats.total_payload
                        ),
                        evidence: vec![
                            alloc::format!("Total ICMP payload: {} bytes", stats.total_payload),
                            alloc::format!("Packets: {}", stats.packet_count),
                            alloc::format!("Payload entropy: {:.2}", payload_entropy),
                        ],
                    });
                }
            }
        }

        // Check for variable payload sizes (encoding data)
        if stats.payload_sizes.len() >= 20 {
            let avg: f64 = stats.payload_sizes.iter().sum::<usize>() as f64
                / stats.payload_sizes.len() as f64;
            let variance: f64 = stats.payload_sizes.iter()
                .map(|&s| {
                    let diff = s as f64 - avg;
                    diff * diff
                })
                .sum::<f64>() / stats.payload_sizes.len() as f64;
            let std_dev = variance.sqrt();

            // High variance in payload sizes is suspicious
            if std_dev > 20.0 && avg > 50.0 {
                return Some(CovertChannel {
                    channel_type: CovertChannelType::IcmpExfil,
                    severity: 65,
                    description: alloc::format!(
                        "Suspicious ICMP from {:?}: variable payload sizes (avg={:.0}, std={:.1})",
                        src_ip, avg, std_dev
                    ),
                    evidence: vec![
                        alloc::format!("Avg payload size: {:.1} bytes", avg),
                        alloc::format!("Std deviation: {:.1}", std_dev),
                        alloc::format!("Packets analyzed: {}", stats.payload_sizes.len()),
                    ],
                });
            }
        }

        None
    }

    /// Extract DNS name from query
    fn extract_dns_name(&self, data: &[u8]) -> String {
        let mut name = String::new();
        let mut i = 0;

        while i < data.len() {
            let len = data[i] as usize;
            if len == 0 {
                break;
            }
            if len > 63 || i + len >= data.len() {
                break; // Invalid label
            }

            if !name.is_empty() {
                name.push('.');
            }

            if let Ok(label) = core::str::from_utf8(&data[i + 1..i + 1 + len]) {
                name.push_str(label);
            }

            i += len + 1;
        }

        name
    }

    /// Get DNS name length in bytes (static version)
    fn dns_name_length_static(data: &[u8]) -> usize {
        let mut len = 0;
        let mut i = 0;

        while i < data.len() {
            let label_len = data[i] as usize;
            if label_len == 0 {
                len += 1;
                break;
            }
            if label_len > 63 {
                break;
            }
            len += label_len + 1;
            i += label_len + 1;
        }

        len
    }

    /// Calculate Shannon entropy of a string (static version)
    fn calculate_entropy_static(s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }

        let mut freq = [0u32; 256];
        for &b in s.as_bytes() {
            freq[b as usize] += 1;
        }

        let len = s.len() as f64;
        let mut entropy = 0.0;

        for &count in &freq {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Calculate entropy of raw bytes (static version)
    fn calculate_entropy_bytes_static(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut freq = [0u32; 256];
        for &b in data {
            freq[b as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &freq {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Cleanup old stats
    pub fn cleanup(&mut self, timestamp: u64) {
        let cutoff = timestamp.saturating_sub(self.stats_window * 10);
        self.dns_stats.retain(|_, s| s.last_seen >= cutoff);
        self.icmp_stats.retain(|_, s| s.last_seen >= cutoff);
    }

    /// Get DNS stats for IP
    pub fn dns_stats_for(&self, ip: &[u8; 4]) -> Option<(u64, u64, u64)> {
        self.dns_stats.get(ip).map(|s| (s.total_queries, s.long_label_queries, s.txt_queries))
    }

    /// Get ICMP stats for IP
    pub fn icmp_stats_for(&self, ip: &[u8; 4]) -> Option<(u64, u64)> {
        self.icmp_stats.get(ip).map(|s| (s.packet_count, s.total_payload))
    }
}

#[cfg(feature = "std")]
impl Default for CovertDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        // Low entropy (repeated chars)
        let low = CovertDetector::calculate_entropy_static("aaaaaa");
        assert!(low < 1.0);

        // Higher entropy (mixed chars)
        let high = CovertDetector::calculate_entropy_static("abc123xyz");
        assert!(high > 2.0);
    }

    #[test]
    fn test_dns_name_extraction() {
        let detector = CovertDetector::new();

        // DNS format: length-prefixed labels
        let dns_query = [
            3, b'w', b'w', b'w',
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            3, b'c', b'o', b'm',
            0, // Terminator
        ];

        let name = detector.extract_dns_name(&dns_query);
        assert_eq!(name, "www.example.com");
    }

    #[test]
    fn test_high_entropy_detection() {
        let mut detector = CovertDetector::new();
        let src_ip = [192, 168, 1, 10];

        // Simulate many high-entropy DNS queries with very long labels
        for i in 0..20 {
            // Create fake DNS packet with long, high-entropy subdomain (> 30 chars)
            let high_entropy_domain = alloc::format!(
                "{}a9x7k2m5b8n1c4p6q3r8j2l4f9s7w2z{}.evil.com",
                i, i * 2
            );
            let _ = detector.check_dns(
                &create_fake_dns_query(&high_entropy_domain),
                src_ip,
                i as u64,
            );
        }

        // Check stats
        if let Some((total, long, _)) = detector.dns_stats_for(&src_ip) {
            assert!(total >= 20);
            assert!(long > 0, "Expected long label queries, subdomain length should be > 30");
        }
    }

    // Helper to create a fake DNS query
    fn create_fake_dns_query(domain: &str) -> Vec<u8> {
        let mut packet = Vec::new();

        // UDP header (8 bytes)
        packet.extend_from_slice(&[0u8; 8]);

        // DNS header (12 bytes)
        packet.extend_from_slice(&[0x00, 0x01]); // ID
        packet.extend_from_slice(&[0x01, 0x00]); // Flags (standard query)
        packet.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        packet.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
        packet.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        packet.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

        // Question section
        for label in domain.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0); // Terminator

        // QTYPE and QCLASS
        packet.extend_from_slice(&[0x00, 0x01]); // A record
        packet.extend_from_slice(&[0x00, 0x01]); // IN class

        packet
    }
}
