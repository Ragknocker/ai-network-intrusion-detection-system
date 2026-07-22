import React from 'react';
import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import MetricsOverview from './MetricsOverview';

describe('MetricsOverview component', () => {
  const mockMetrics = {
    packetRate: 150,
    bandwidth: 5242880, // 5 MB in bytes
    blockedIPs: 12,
    totalAnalyzed: 4500
  };

  it('renders all metric card titles and calculated values correctly', () => {
    render(<MetricsOverview metrics={mockMetrics} />);

    expect(screen.getByText(/Active Flows/i)).toBeInTheDocument();
    expect(screen.getByText('150')).toBeInTheDocument();
    expect(screen.getByText('pps')).toBeInTheDocument();

    expect(screen.getByText(/Bandwidth/i)).toBeInTheDocument();
    expect(screen.getByText('5.00')).toBeInTheDocument(); // 5242880 / 1024 / 1024
    expect(screen.getByText('MB/s')).toBeInTheDocument();

    expect(screen.getByText(/Blocked IPs/i)).toBeInTheDocument();
    expect(screen.getByText('12')).toBeInTheDocument();

    expect(screen.getByText(/Total Analyzed/i)).toBeInTheDocument();
    expect(screen.getByText('4,500')).toBeInTheDocument();
  });
});
