import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import ThreatAlertPanel from './ThreatAlertPanel';

describe('ThreatAlertPanel component', () => {
  const mockAlerts = [
    {
      id: '1',
      type: 'SQL Injection',
      severity: 'Critical',
      timestamp: '10:00:00.123',
      source: '192.168.1.50',
      target: '192.168.1.100:80',
      geo: 'RU',
      payloadInfo: "' OR 1=1 --"
    },
    {
      id: '2',
      type: 'Port Scan',
      severity: 'Medium',
      timestamp: '10:00:01.456',
      source: '10.0.0.5',
      target: '192.168.1.100:443',
      geo: 'CN',
      payloadInfo: 'SYN-Stealth'
    }
  ];

  it('renders "No active threats detected" when alerts array is empty', () => {
    render(<ThreatAlertPanel alerts={[]} onClear={() => {}} />);
    expect(screen.getByText(/No active threats detected/i)).toBeInTheDocument();
  });

  it('renders all alert cards when alerts are present', () => {
    render(<ThreatAlertPanel alerts={mockAlerts} onClear={() => {}} />);
    
    expect(screen.getByText(/SQL Injection/i)).toBeInTheDocument();
    expect(screen.getByText(/Port Scan/i)).toBeInTheDocument();
    expect(screen.getByText('Critical')).toBeInTheDocument();
    expect(screen.getByText('Medium')).toBeInTheDocument();
    expect(screen.getByText("' OR 1=1 --")).toBeInTheDocument();
    expect(screen.getByText('SYN-Stealth')).toBeInTheDocument();
  });

  it('calls onClear handler when clear button is clicked', () => {
    const handleClear = vi.fn();
    render(<ThreatAlertPanel alerts={mockAlerts} onClear={handleClear} />);

    const clearBtn = screen.getByTitle('Clear Alerts');
    fireEvent.click(clearBtn);

    expect(handleClear).toHaveBeenCalledTimes(1);
  });
});
