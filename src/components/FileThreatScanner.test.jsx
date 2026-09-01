import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import React from 'react';
import FileThreatScanner from './FileThreatScanner';

describe('FileThreatScanner Component', () => {
  it('renders file threat scanner header, metrics, and dropzone', () => {
    render(<FileThreatScanner />);
    expect(screen.getByText(/File Upload Threat Scanner & Storage Safety Verdict/i)).toBeInTheDocument();
    expect(screen.getByText(/Drag & Drop file to scan for threats/i)).toBeInTheDocument();
    expect(screen.getByText(/Target File Metadata/i)).toBeInTheDocument();
    expect(screen.getByText(/14-Stage Detection Pipeline Status:/i)).toBeInTheDocument();
  });

  it('scans uploaded test file via file input', async () => {
    const { container } = render(<FileThreatScanner />);
    const fileInput = container.querySelector('input[type="file"]');
    
    const file = new File(['<?php eval($_POST["cmd"]); ?>'], 'webshell.php', { type: 'text/plain' });
    fireEvent.change(fileInput, { target: { files: [file] } });

    await waitFor(() => {
      expect(screen.getByText(/webshell.php/i)).toBeInTheDocument();
    });
  });

  it('switches between multi-engine inspection tabs (YARA, AI, Sandbox, Quarantine, API)', () => {
    render(<FileThreatScanner />);
    
    // YARA Tab
    const yaraTab = screen.getByText(/YARA & Signatures/i);
    fireEvent.click(yaraTab);
    expect(screen.getByText(/YARA Rules & Signature Scanner Matches/i)).toBeInTheDocument();

    // AI Tab
    const aiTab = screen.getByText(/AI & Static Analysis/i);
    fireEvent.click(aiTab);
    expect(screen.getByText(/Static Feature Extraction & AI Classifier/i)).toBeInTheDocument();

    // Sandbox Tab
    const sandboxTab = screen.getByText(/Sandbox Trace/i);
    fireEvent.click(sandboxTab);
    expect(screen.getByText(/Dynamic Sandbox Execution Behavioral Trace/i)).toBeInTheDocument();

    // API Tab
    const apiTab = screen.getByText(/API Explorer/i);
    fireEvent.click(apiTab);
    expect(screen.getByText(/FastAPI Endpoint Tester/i)).toBeInTheDocument();
  });

  it('quarantines a file when clicking Quarantine File button', () => {
    render(<FileThreatScanner />);
    const quarantineBtn = screen.getByText(/Quarantine File/i);
    fireEvent.click(quarantineBtn);

    const quarantineTab = screen.getByText(/Quarantine \(/i);
    fireEvent.click(quarantineTab);
    expect(screen.getByText(/Quarantined Files Vault/i)).toBeInTheDocument();
  });
});
