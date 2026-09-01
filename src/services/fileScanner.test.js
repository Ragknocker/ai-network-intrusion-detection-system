import { describe, it, expect } from 'vitest';
import { 
  scanFileContent, computeFileHash, FILE_PRESETS,
  computeYaraScore, computeSignatureScore, computeAiScore,
  computeSandboxScore, computeReputationScore,
  getQuarantinedFiles, quarantineFile, restoreQuarantinedFile, deleteQuarantinedFile
} from './fileScanner';

describe('fileScanner Service - Multi-Engine Architecture', () => {
  it('computes a valid SHA-256 hash string', async () => {
    const hash = await computeFileHash('test content');
    expect(hash).toBeDefined();
    expect(hash.length).toBeGreaterThanOrEqual(16);
  });

  it('correctly classifies a malicious PHP WebShell as UNSAFE and QUARANTINE decision', () => {
    const phpContent = `<?php if(isset($_POST['cmd'])) { eval(base64_decode($_POST['cmd'])); system("nc -e /bin/sh"); } ?>`;
    const result = scanFileContent('malicious_webshell.php', phpContent, 512);

    expect(result.status).toBe('Threat / Malicious');
    expect(result.decision).toBe('QUARANTINE');
    expect(result.disposition).toBe('UNSAFE - QUARANTINE / DELETE IMMEDIATELY');
    expect(result.threatScore).toBeGreaterThan(60);
    expect(result.engineBreakdown).toBeDefined();
    expect(result.engineBreakdown.aiScore).toBeGreaterThan(0);
    expect(result.flaggedLines.length).toBeGreaterThan(0);
  });

  it('detects embedded JavaScript and OpenAction exploits in PDF documents', () => {
    const pdfContent = `%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.launchURL('http://malicious.com');) >> >>\nendobj`;
    const result = scanFileContent('exploit.pdf', pdfContent, 890);

    expect(result.fileType).toBe('PDF Document');
    expect(result.disposition).toBe('UNSAFE - QUARANTINE / DELETE IMMEDIATELY');
    expect(result.yaraMatches.length).toBeGreaterThan(0);
    expect(result.flaggedLines.some(l => l.category.includes('JavaScript') || l.category.includes('OpenAction'))).toBe(true);
  });

  it('correctly classifies network log files containing DDoS and SQLi attacks', () => {
    const logContent = `18:24:01,192.168.1.1,192.168.1.100,DDoS SYN Flood,1500\n18:24:02,192.168.1.1,192.168.1.100,UNION SELECT OR 1=1`;
    const result = scanFileContent('traffic_log.csv', logContent, 1024);

    expect(result.threatScore).toBeGreaterThan(30);
    expect(result.flaggedLines.some(l => l.category.includes('DDoS'))).toBe(true);
  });

  it('classifies safe JSON configuration files as ALLOW decision and SAFE TO KEEP', () => {
    const jsonContent = `{\n  "appName": "AI-NIDS",\n  "version": "1.0.0",\n  "active": true\n}`;
    const result = scanFileContent('config.json', jsonContent, 200);

    expect(result.status).toBe('Safe / Clean');
    expect(result.decision).toBe('ALLOW');
    expect(result.disposition).toBe('SAFE TO KEEP');
    expect(result.threatScore).toBeLessThan(30);
    expect(result.flaggedLines).toHaveLength(0);
  });

  it('handles empty files gracefully', () => {
    const result = scanFileContent('empty.txt', '', 0);
    expect(result.status).toBe('Safe / Clean');
    expect(result.decision).toBe('ALLOW');
    expect(result.disposition).toBe('SAFE TO KEEP');
    expect(result.lineCount).toBe(1);
  });

  it('evaluates individual sub-engines: YARA, Signature, AI, Sandbox, Reputation', () => {
    const yara = computeYaraScore('WannaCrypt WNCRY!', 'Executable / Script Binary', 'exe');
    expect(yara.score).toBeGreaterThan(50);
    expect(yara.matches.length).toBeGreaterThan(0);

    const sig = computeSignatureScore('ed015a5404e1575312226e370d857f17b5e6841500f483c773e7f2254a4c28d2', 'WannaCrypt');
    expect(sig.score).toBeGreaterThan(50);

    const ai = computeAiScore({ flaggedPatternCount: 2, hasAutoAction: true }, 6.2, 'Executable / Script Binary', 'exe');
    expect(ai.score).toBeGreaterThan(50);

    const sb = computeSandboxScore('WannaCrypt', 'Executable / Script Binary', 'exe');
    expect(sb.score).toBeGreaterThan(50);
    expect(sb.events.length).toBeGreaterThan(0);

    const rep = computeReputationScore('hash', 'WannaCrypt');
    expect(rep.score).toBeGreaterThan(50);
  });

  it('manages quarantine vault lifecycle (add, list, restore, delete)', () => {
    const result = scanFileContent('virus.exe', 'WannaCrypt payload', 500);
    const item = quarantineFile(result);
    expect(item).toHaveProperty('id');
    expect(item.fileName).toBe('virus.exe');

    const vault = getQuarantinedFiles();
    expect(vault.some(q => q.id === item.id)).toBe(true);

    deleteQuarantinedFile(item.id);
    expect(getQuarantinedFiles().some(q => q.id === item.id)).toBe(false);

    const item2 = quarantineFile(result);
    restoreQuarantinedFile(item2.id);
    expect(getQuarantinedFiles().some(q => q.id === item2.id)).toBe(false);
  });

  it('provides real-world preset sample files', () => {
    expect(FILE_PRESETS.length).toBeGreaterThanOrEqual(4);
    expect(FILE_PRESETS[0]).toHaveProperty('name');
    expect(FILE_PRESETS[0]).toHaveProperty('content');
  });
});
