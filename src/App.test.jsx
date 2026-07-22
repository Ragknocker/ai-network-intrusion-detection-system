import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import App from './App';

// Mock recharts for jsdom compatibility
vi.mock('recharts', async () => {
  const original = await vi.importActual('recharts');
  return {
    ...original,
    ResponsiveContainer: ({ children }) => <div>{children}</div>,
  };
});

describe('App top-to-bottom integration', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('renders navbar, metrics overview, live traffic monitor, threat alerts, and simulator by default', () => {
    render(<App />);

    expect(screen.getByText(/Active Flows/i)).toBeInTheDocument();
    expect(screen.getByText('Live Network Stream')).toBeInTheDocument();
    expect(screen.getByText('Active Threats')).toBeInTheDocument();
    expect(screen.getByText('Attack Simulator')).toBeInTheDocument();
  });

  it('navigates between Dashboard and Model Performance tabs smoothly', () => {
    render(<App />);

    const modelsTab = screen.getByRole('button', { name: /Model Performance/i });
    fireEvent.click(modelsTab);

    expect(screen.getByText(/Global Accuracy/i)).toBeInTheDocument();
    expect(screen.getByText('Hybrid Forest-AE v2.1')).toBeInTheDocument();

    const dashboardTab = screen.getByRole('button', { name: /Live Dashboard/i });
    fireEvent.click(dashboardTab);

    expect(screen.getByText('Live Network Stream')).toBeInTheDocument();
  });
});
