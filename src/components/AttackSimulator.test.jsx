import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import AttackSimulator from './AttackSimulator';
import { triggerAttack } from '../services/trafficGenerator';

vi.mock('../services/trafficGenerator', () => ({
  triggerAttack: vi.fn(),
}));

describe('AttackSimulator component', () => {
  it('renders attack simulation header and all attack buttons', () => {
    render(<AttackSimulator />);
    
    expect(screen.getByText('Attack Simulator')).toBeInTheDocument();
    expect(screen.getByText(/DDoS Flood/i)).toBeInTheDocument();
    expect(screen.getByText(/Port Scan/i)).toBeInTheDocument();
    expect(screen.getByText(/SQL Injection/i)).toBeInTheDocument();
    expect(screen.getByText(/Malware C2/i)).toBeInTheDocument();
    expect(screen.getByText(/Zero-Day/i)).toBeInTheDocument();
  });

  it('triggers attack service when DDoS Flood button is clicked', () => {
    render(<AttackSimulator />);
    
    const ddosButton = screen.getByText(/DDoS Flood/i);
    fireEvent.click(ddosButton);

    expect(triggerAttack).toHaveBeenCalledWith('DDoS');
  });

  it('triggers attack service when SQL Injection button is clicked', () => {
    render(<AttackSimulator />);
    
    const sqlButton = screen.getByText(/SQL Injection/i);
    fireEvent.click(sqlButton);

    expect(triggerAttack).toHaveBeenCalledWith('SQL Injection');
  });
});
