import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { generateIP, generatePort, generatePacket, triggerAttack } from './trafficGenerator';

describe('trafficGenerator service', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('generateIP returns a valid IPv4 address string', () => {
    const ip = generateIP();
    expect(typeof ip).toBe('string');
    const parts = ip.split('.');
    expect(parts.length).toBe(4);
    parts.forEach(part => {
      const num = parseInt(part, 10);
      expect(num).toBeGreaterThanOrEqual(0);
      expect(num).toBeLessThanOrEqual(255);
    });
  });

  it('generatePort returns a port in range 0-65535', () => {
    const port = generatePort();
    expect(typeof port).toBe('number');
    expect(port).toBeGreaterThanOrEqual(0);
    expect(port).toBeLessThanOrEqual(65535);
  });

  it('generatePacket returns a well-formed packet object', () => {
    const packet = generatePacket();
    expect(packet).toHaveProperty('id');
    expect(packet).toHaveProperty('timestamp');
    expect(packet).toHaveProperty('srcIP');
    expect(packet).toHaveProperty('destIP');
    expect(packet).toHaveProperty('srcPort');
    expect(packet).toHaveProperty('destPort');
    expect(packet).toHaveProperty('protocol');
    expect(packet).toHaveProperty('size');
    expect(packet).toHaveProperty('classification');
    expect(packet).toHaveProperty('threatScore');
    expect(packet).toHaveProperty('geo');
    expect(packet).toHaveProperty('payloadInfo');
  });

  it('triggerAttack forces subsequent packets to use the specified attack type', () => {
    triggerAttack('SQL Injection');
    const packet = generatePacket();
    expect(packet.classification).toBe('SQL Injection');
    expect(packet.destPort).toBe(80);
    expect(packet.threatScore).toBeGreaterThanOrEqual(75);

    // Fast-forward timer past 5000ms
    vi.advanceTimersByTime(5001);

    // After timeout, random generation resumes
    const normalOrRandomPacket = generatePacket();
    expect(normalOrRandomPacket).toBeDefined();
  });
});
