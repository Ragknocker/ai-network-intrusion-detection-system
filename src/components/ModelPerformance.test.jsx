import React from 'react';
import { render, screen } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import ModelPerformance from './ModelPerformance';

// Mock Recharts ResponsiveContainer for jsdom environment compatibility
vi.mock('recharts', async () => {
  const original = await vi.importActual('recharts');
  return {
    ...original,
    ResponsiveContainer: ({ children }) => (
      <div style={{ width: 800, height: 400 }}>{children}</div>
    ),
  };
});

describe('ModelPerformance component', () => {
  it('renders summary metrics and model performance headers correctly', () => {
    render(<ModelPerformance />);

    expect(screen.getByText(/Global Accuracy/i)).toBeInTheDocument();
    expect(screen.getByText('96.4%')).toBeInTheDocument();
    expect(screen.getByText(/Active Model/i)).toBeInTheDocument();
    expect(screen.getByText('Hybrid Forest-AE v2.1')).toBeInTheDocument();
    expect(screen.getByText(/Class-wise Performance/i)).toBeInTheDocument();
    expect(screen.getByText(/ROC Curve/i)).toBeInTheDocument();
  });
});
