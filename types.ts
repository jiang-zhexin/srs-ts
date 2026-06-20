export type Bytes = Uint8Array<ArrayBuffer>;

export type succinctSet = {
  leaves: BigUint64Array;
  labelBitmap: BigUint64Array;
  labels: Uint8Array;
  ranks: Int32Array;
  selects: Int32Array;
};

export type Network = "tcp" | "udp" | "icmp";
export type NetworkType = "wifi" | "cellular" | "ethernet" | "other";

export type Version = 1 | 2 | 3 | 4 | 5;
export type Rule = rule<v5>;
export type DefaultRule = v5;
export type LogicalRule = logicalRule<v5>;

export type RuleSet =
  | { version: 1 | 2; rules: rule<v1>[] }
  | { version: 3; rules: rule<v3>[] }
  | { version: 4; rules: rule<v4>[] }
  | { version: 5; rules: rule<v5>[] };

type v1 = {
  type?: "default";
  query_type?: listable<string | number>;
  network?: listable<Network>;
  domain?: listable<string>;
  domain_suffix?: listable<string>;
  domain_keyword?: listable<string>;
  domain_regex?: listable<string>;
  source_ip_cidr?: listable<string>;
  ip_cidr?: listable<string>;
  source_port?: listable<number>;
  source_port_range?: listable<string>;
  port?: listable<number>;
  port_range?: listable<string>;
  process_name?: listable<string>;
  process_path?: listable<string>;
  process_path_regex?: listable<string>;
  package_name?: listable<string>;
  wifi_ssid?: listable<string>;
  wifi_bssid?: listable<string>;
  invert?: boolean;
};

type v3 = v1 & {
  network_type?: listable<NetworkType>;
  network_is_expensive?: boolean;
  network_is_constrained?: boolean;
};

type v4 = v3 & {
  network_interface_address?: Partial<Record<NetworkType, listable<string>>>;
  default_interface_address?: listable<string>;
};

type v5 = v4 & {
  package_name_regex?: listable<string>;
};

type rule<T> = T | logicalRule<T>;
type logicalRule<T> = {
  type: "logical";
  mode: "and" | "or";
  rules: rule<T>[];
  invert?: boolean;
};

type listable<T> = T[];
