import React from 'react';
import { render, screen, act, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import LiveTrafficMonitor from './LiveTrafficMonitor';

describe('LiveTrafficMonitor component', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('renders Live Network Stream header and PAUSE button', () => {
    render(<LiveTrafficMonitor onNewPacket={() => {}} />);
    expect(screen.getByText('Live Network Stream')).toBeInTheDocument();
    expect(screen.getByText('PAUSE')).toBeInTheDocument();
  });

  it('emits new packets periodically and calls onNewPacket callback', () => {
    const handleNewPacket = vi.fn();
    render(<LiveTrafficMonitor onNewPacket={handleNewPacket} />);

    act(() => {
      vi.advanceTimersByTime(1600);
    });

    expect(handleNewPacket).toHaveBeenCalled();
  });

  it('pauses and resumes traffic stream on button toggle', () => {
    const handleNewPacket = vi.fn();
    render(<LiveTrafficMonitor onNewPacket={handleNewPacket} />);

    const pauseBtn = screen.getByText('PAUSE');
    fireEvent.click(pauseBtn);

    expect(screen.getByText('RESUME')).toBeInTheDocument();

    const callCountAtPause = handleNewPacket.mock.calls.length;

    act(() => {
      vi.advanceTimersByTime(2000);
    });

    // Should not receive extra calls while paused
    expect(handleNewPacket.mock.calls.length).toBe(callCountAtPause);

    const resumeBtn = screen.getByText('RESUME');
    fireEvent.click(resumeBtn);

    act(() => {
      vi.advanceTimersByTime(1600);
    });

    expect(handleNewPacket.mock.calls.length).toBeGreaterThan(callCountAtPause);
  });
});
