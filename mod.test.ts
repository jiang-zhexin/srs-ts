import { assertEquals } from "@std/assert";
import { readSrs, writeSrs } from "./mod.ts";
import type { RuleSet } from "./types.ts";

const testData: RuleSet = {
  version: 5,
  rules: [
    {
      domain_suffix: [
        "cdn-telegram.org",
        "comments.app",
        "contest.com",
        "telegra.ph",
      ],
      ip_cidr: [
        "91.105.192.0/23",
        "91.108.4.0/22",
        "2001:67c:4e8::/48",
        "2a0a:f280::/32",
      ],
      query_type: [1, 28],
      network: ["tcp", "udp"],
      domain: ["example.com", "test.example.org"],
      domain_keyword: ["ads", "tracker", "analytics"],
      domain_regex: [".*\\.doubleclick\\.net$", ".*\\.google-analytics\\.com$"],
      source_ip_cidr: ["10.0.0.0/8", "172.16.0.0/12"],
      source_port: [80, 443, 8443],
      source_port_range: ["8000-9000", "6881-6889"],
      port: [53, 8080, 9090],
      port_range: ["1000-2000", "30000-31000"],
      process_path: ["/usr/bin/app1", "C:\\Program Files\\App2\\app2.exe"],
      process_path_regex: [".*/node\\.exe$", ".*\\\\python\\.exe$"],
      package_name: ["com.example.app", "org.company.game"],
      package_name_regex: ["com\\.example\\..*", "com\\.google\\..*"],
      wifi_ssid: ["MyWiFi", "OfficeNet"],
      wifi_bssid: ["00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"],
      network_type: ["wifi", "cellular", "ethernet"],
      network_is_expensive: true,
      network_is_constrained: true,
      default_interface_address: ["10.0.0.1/32", "192.168.1.1/32"],
      invert: true,
    },
    {
      type: "logical",
      mode: "or",
      rules: [
        {
          domain_suffix: ["logical-a.test"],
          network: ["tcp"],
        },
        {
          domain_keyword: ["blocked"],
          ip_cidr: ["10.0.0.0/8"],
        },
      ],
    },
    {
      network_interface_address: {
        wifi: ["10.0.0.0/24", "192.168.0.0/16"],
        cellular: ["100.64.0.0/10"],
        ethernet: ["fe80::/10"],
      },
      default_interface_address: ["0.0.0.0/0"],
    },
  ],
};

Deno.test("test", async () => {
  const bin = writeSrs(testData);
  const result = await readSrs(bin);

  assertEquals(result, testData);
});
