import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import React from 'react';
import UrlInspector from './UrlInspector';

describe('UrlInspector Component (Accurate & Zero Preset Residue)', () => {
  it('renders URL Inspector header, engine status, empty input, and prompt', () => {
    render(<UrlInspector />);
    expect(screen.getByText(/URL Threat Inspector/i)).toBeInTheDocument();
    expect(screen.getByText(/ACCURATE REAL-TIME ENGINE/i)).toBeInTheDocument();
    expect(screen.getByText(/Engine Active/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/Enter URL to inspect/i)).toHaveValue('');
    expect(screen.getByText(/Enter a URL to Inspect/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Inspect URL/i })).toBeInTheDocument();
  });

  it('accurately inspects a clean searched URL with 0% threat score', async () => {
    render(<UrlInspector />);
    const urlInput = screen.getByPlaceholderText(/Enter URL to inspect/i);
    fireEvent.change(urlInput, { target: { value: 'https://www.google.com/search?q=cybersecurity' } });

    const inspectBtn = screen.getByRole('button', { name: /Inspect URL/i });
    fireEvent.click(inspectBtn);

    await waitFor(() => {
      expect(screen.getByText(/SAFE \/ LEGITIMATE/i)).toBeInTheDocument();
      expect(screen.getAllByText(/ALLOW TRAFFIC/i).length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText(/0%/i).length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText(/URL Anatomy & Features/i)).toBeInTheDocument();
      expect(screen.getByText(/Domain Intelligence/i)).toBeInTheDocument();
    });
  });

  it('accurately detects a malicious phishing URL with high threat score and risk factors', async () => {
    render(<UrlInspector />);
    const urlInput = screen.getByPlaceholderText(/Enter URL to inspect/i);
    fireEvent.change(urlInput, { target: { value: 'http://secure-paypal-login.xyz/login.php?id=84920' } });

    const inspectBtn = screen.getByRole('button', { name: /Inspect URL/i });
    fireEvent.click(inspectBtn);

    await waitFor(() => {
      expect(screen.getByText(/MALICIOUS \/ PHISHING/i)).toBeInTheDocument();
      expect(screen.getAllByText(/BLOCK IMMEDIATELY/i).length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText(/95%/i).length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText(/Identified Risk Factors/i)).toBeInTheDocument();
      expect(screen.getAllByText(/Typosquatting brand spoofing detected/i).length).toBeGreaterThanOrEqual(1);
    });
  });

  it('removes preset selection tag when user types their own custom URL', () => {
    render(<UrlInspector />);
    const c2Preset = screen.getByRole('button', { name: /Malicious C2/i });
    fireEvent.click(c2Preset);

    expect(screen.getByText(/Sample Preset:/i)).toBeInTheDocument();

    const urlInput = screen.getByPlaceholderText(/Enter URL to inspect/i);
    fireEvent.change(urlInput, { target: { value: 'https://openai.com' } });

    // Preset tag should be cleared
    expect(screen.queryByText(/Sample Preset:/i)).not.toBeInTheDocument();
    expect(urlInput.value).toBe('https://openai.com');
  });

  it('clears input and returns to empty state when clicking clear button', () => {
    render(<UrlInspector />);
    const urlInput = screen.getByPlaceholderText(/Enter URL to inspect/i);
    fireEvent.change(urlInput, { target: { value: 'https://example.com' } });

    const clearBtn = screen.getByTitle(/Clear input/i);
    fireEvent.click(clearBtn);

    expect(urlInput.value).toBe('');
    expect(screen.getByText(/Enter a URL to Inspect/i)).toBeInTheDocument();
  });

  it('automatically inspects target when passed via inspectTarget prop', () => {
    render(<UrlInspector inspectTarget={{ value: 'http://xn--pple-43d.com/login' }} />);
    const urlInput = screen.getByPlaceholderText(/Enter URL to inspect/i);
    expect(urlInput.value).toBe('http://xn--pple-43d.com/login');
    expect(screen.getByText(/Unified Threat Score:/i)).toBeInTheDocument();
  });
});
