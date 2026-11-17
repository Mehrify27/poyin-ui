export interface SupportedLocale {
  code: string;
  name: string;
  icon: string;
  rtl: boolean;
}

export interface PwaMeta {
  manifestUrl: string;
  swUrl: string;
  scope: string;
}

export interface RuntimeConfig {
  basePath: string;
  appBasePath: string;
  apiBasePath: string;
  wsPath: string;
  manifestUrl?: string;
  swUrl?: string;
  version?: string;
  assetVersion?: string;
}

export interface SessionUser {
  id: number;
  username: string;
  isSuperAdmin: boolean;
  isReseller: boolean;
  twoFactorEnable: boolean;
}

export interface ResellerProfile {
  isReseller: boolean;
  unlimited?: boolean;
  allowanceBytes?: number;
  spentBytes?: number;
  availableBytes?: number;
  daysPerGb?: number;
  minCreateGb?: number;
  minAddGb?: number;
  allowExternalProxy?: boolean;
  allowOverview?: boolean;
  allowOverviewManage?: boolean;
}

export interface DonateEntry {
  Chain: string;
  Address: string;
}

export interface ProtocolCapabilities {
  awgAvailable: boolean;
  awgKernel: boolean;
  awgUserspace: boolean;
  awgMode: "kernel+userspace" | "userspace" | "kernel" | "missing" | string;
  awgVersion?: string;
  hysteria2Available: boolean;
  hysteria2Version?: string;
  mtprotoAvailable: boolean;
  mtprotoVersion?: string;
  wireguardKernel: boolean;
  greKernel: boolean;
  xrayAvailable: boolean;
  xrayVersion?: string;
  xrayPatched: boolean;
}

export interface ProtocolEngineInfo {
  id: string;
  title: string;
  category: string;
  engineName: string;
  protocols: string;
  available: boolean;
  source: string;
  version?: string;
  banner?: string;
  binaryPath?: string;
  updateTarget?: string;
  customPatched?: boolean;
  patchSet?: string[];
  kernelModule?: string;
  kernelLoaded?: boolean;
  kernelRelease?: string;
  helperTools?: string[];
  detail?: string;
}

export interface CapabilitiesPayload {
  os: string;
  arch: string;
  provisioned: boolean;
  missingProtocols: string[];
  protocols: ProtocolCapabilities;
  panelTlsEnabled: boolean;
  subTlsEnabled: boolean;
  telegramEnabled: boolean;
  engines: ProtocolEngineInfo[];
}

export interface BootstrapUIData {
  legacyInboundForm: boolean;
  serverName: string;
  defaults: Record<string, unknown>;
  backupPanelName?: string;
  backupDomain?: string;
  telegramEnabled?: boolean;
  panelTlsEnabled?: boolean;
  subTlsEnabled?: boolean;
}

export interface BootstrapPayload {
  version: string;
  assetVersion: string;
  basePath: string;
  appBasePath: string;
  apiBasePath: string;
  wsPath: string;
  authenticated: boolean;
  defaultTheme: string;
  defaultLocale: string;
  supportedLocales: SupportedLocale[];
  host: string;
  pwa: PwaMeta;
  user?: SessionUser;
  perms?: Record<string, boolean>;
  reseller?: ResellerProfile;
  landingPath?: string;
  ui?: BootstrapUIData;
  capabilities?: CapabilitiesPayload;
  donate?: DonateEntry[];
}

export interface ApiEnvelope<T = unknown> {
  success: boolean;
  msg: string;
  obj: T;
}

export interface CoreBinaryInventory {
  core: string;
  serviceCore: string;
  protocols?: string;
  activePath: string;
  bundledPath?: string;
  customPath?: string;
  customDir?: string;
  source: string;
  version: string;
  installedVersion?: string;
  sha256?: string;
  hasBackup: boolean;
  customPatched?: boolean;
  binaryMode?: string;
  supportsSpeedLimit?: boolean;
  supportsNativeForkProtocols?: boolean;
  speedLimitEngine?: string;
  forkProtocolEngine?: string;
  patchSet?: string[];
  upstreamRepo?: string;
  upstreamUrl?: string;
  updateMode?: string;
  autoUpdatable?: boolean;
  upstreamWarning?: string;
}

export interface XrayBinaryCapabilities {
  binaryMode: string;
  supportsSpeedLimit: boolean;
  supportsNativeForkProtocols: boolean;
}

export interface CoreVersionsResponse {
  binaries: CoreBinaryInventory[];
  engines: ProtocolEngineInfo[];
  xrayCapabilities?: XrayBinaryCapabilities;
  forkProtocolEngine?: string;
  speedLimitEngine?: string;
}

export interface NetworkTuningStatus {
  osSupported: boolean;
  kernelRelease: string;
  containerized: boolean;
  readOnlySysctl: boolean;
  bbrAvailable: boolean;
  bbrActive: boolean;
  bestBBRVariant?: string;
  congestionControl: string;
  defaultQdisc: string;
  activeProfile?: string;
  canRevert?: boolean;
  message?: string;
}

export interface ServerStatusSnapshot {
  cpu: number;
  cpuCores: number;
  mem: { current: number; total: number };
  swap: { current: number; total: number };
  disk: { current: number; total: number };
  uptime: number;
  loads: number[];
  xray: { state: string; errorMsg?: string; version?: string };
  netIO: { up: number; down: number };
  netTraffic: { sent: number; recv: number };
  tcpCount: number;
  udpCount: number;
  publicIP?: { ipv4?: string; ipv6?: string };
}
