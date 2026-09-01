import { describe, it, expect } from 'vitest';
import { 
  analyzeUrlAndFunction, extractUrlFeatures, checkUrlBlacklist, 
  getDomainIntelligence, classifyUrlAi, inspectHttpRequest, 
  inspectFunctionCall, checkThreatIntel, URL_PRESETS 
} from './urlInspector';

describe('urlInspector Service - Multi-Engine Architecture', () => {
  it('extracts structural URL features correctly', () => {
    const features = extractUrlFeatures('http://secure-paypal-login.xyz/login.php?id=123');
    expect(features.domain).toBe('secure-paypal-login.xyz');
    expect(features.hasHttps).toBe(false);
    expect(features.suspiciousKeywords).toContain('paypal');
    expect(features.entropy).toBeGreaterThan(3.5);
  });

  it('detects phishing URL blacklists', () => {
    const blacklist = checkUrlBlacklist('http://secure-paypal-login.xyz/login.php', 'secure-paypal-login.xyz');
    expect(blacklist.score).toBeGreaterThan(50);
    expect(blacklist.matches.length).toBeGreaterThan(0);
  });

  it('fetches domain intelligence metadata', () => {
    const domainIntel = getDomainIntelligence('secure-paypal-login.xyz');
    expect(domainIntel.domain).toBe('secure-paypal-login.xyz');
    expect(domainIntel.domainAgeDays).toBeLessThan(30);
    expect(domainIntel.sslValid).toBe(false);
  });

  it('classifies URLs via AI model simulation', () => {
    const features = extractUrlFeatures('http://secure-paypal-login.xyz/login.php');
    const ai = classifyUrlAi(features, features.entropy);
    expect(ai.score).toBeGreaterThan(40);
    expect(ai.model).toBeDefined();
  });

  it('inspects HTTP requests for SQLi payload attacks', () => {
    const http = inspectHttpRequest('http://192.168.1.100/login.php', 'POST', {}, "username=admin' UNION SELECT 1,2,3--");
    expect(http.score).toBeGreaterThan(70);
    expect(http.attacks.some(a => a.category.includes('SQL Injection'))).toBe(true);
  });

  it('monitors Win32 API function call events', () => {
    const func = inspectFunctionCall('VirtualAlloc', 'cmd.exe', 'process memory injection');
    expect(func.score).toBeGreaterThan(70);
    expect(func.events.some(e => e.api.includes('VirtualAlloc'))).toBe(true);
  });

  it('checks threat intelligence feeds', () => {
    const intel = checkThreatIntel('http://secure-paypal-login.xyz/login.php', 'secure-paypal-login.xyz');
    expect(intel.score).toBeGreaterThan(50);
    expect(intel.vtRatio).toBeDefined();
  });

  it('orchestrates complete URL and function analysis', () => {
    const result = analyzeUrlAndFunction('http://secure-paypal-login.xyz/login.php?id=123', 'GET');
    expect(result.url).toBe('http://secure-paypal-login.xyz/login.php?id=123');
    expect(result.threatScore).toBeGreaterThan(50);
    expect(result.decision).toBeDefined();
    expect(result.engineBreakdown).toBeDefined();
  });

  it('provides real-world preset samples', () => {
    expect(URL_PRESETS.length).toBeGreaterThanOrEqual(4);
    expect(URL_PRESETS[0]).toHaveProperty('name');
    expect(URL_PRESETS[0]).toHaveProperty('url');
  });
});
