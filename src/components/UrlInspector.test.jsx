import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import React from 'react';
import UrlInspector from './UrlInspector';

describe('UrlInspector Component', () => {
  it('renders URL Inspector header, top metrics, and input controls', () => {
    render(<UrlInspector />);
    expect(screen.getByText(/URL & Function Inspector Dashboard/i)).toBeInTheDocument();
    expect(screen.getByText(/Total Scanned URLs/i)).toBeInTheDocument();
    expect(screen.getByText(/14-Stage Detection Pipeline Status:/i)).toBeInTheDocument();
  });

  it('runs URL analysis when clicking Analyze URL & Function button', () => {
    render(<UrlInspector />);
    const analyzeBtn = screen.getByText(/Analyze URL & Function/i);
    fireEvent.click(analyzeBtn);

    expect(screen.getByText(/URL & Session Safety Verdict/i)).toBeInTheDocument();
    expect(screen.getByText(/Analyst Triage Reasons & Contributing Factors/i)).toBeInTheDocument();
  });

  it('analyzes entered custom URL when clicking analyze button', () => {
    render(<UrlInspector />);
    const urlInput = screen.getByPlaceholderText(/Enter URL, domain, percent-encoded/i);
    fireEvent.change(urlInput, { target: { value: 'http://secure-paypal-login.xyz/login.php' } });

    const analyzeBtn = screen.getByText(/Analyze URL & Function/i);
    fireEvent.click(analyzeBtn);

    expect(screen.getByText(/Unified Risk Score:/i)).toBeInTheDocument();
  });

  it('switches between all multi-engine inspection tabs', () => {
    render(<UrlInspector />);

    // Extraction & Normalizer Tab
    const extractTab = screen.getByText(/Extraction & Normalizer/i);
    fireEvent.click(extractTab);
    expect(screen.getByText(/Extraction Layer & URL Normalization Workbench/i)).toBeInTheDocument();

    // Feature Matrix & Intel Tab
    const featureTab = screen.getByText(/Feature Matrix & Intel/i);
    fireEvent.click(featureTab);
    expect(screen.getByText(/Multi-Category Feature Matrix & Domain Intelligence/i)).toBeInTheDocument();

    // 2-Stage AI Classifier Tab
    const aiTab = screen.getByText(/2-Stage AI Classifier/i);
    fireEvent.click(aiTab);
    expect(screen.getByText(/Two-Stage Classification Engine/i)).toBeInTheDocument();

    // SIEM & Auto-Block Tab
    const siemTab = screen.getByText(/SIEM & Auto-Block/i);
    fireEvent.click(siemTab);
    expect(screen.getByText(/SIEM \/ Alerting Integration & Firewall Auto-Block Hook/i)).toBeInTheDocument();

    // Feedback & Drift Store Tab
    const feedbackTab = screen.getByText(/Feedback & Drift Store/i);
    fireEvent.click(feedbackTab);
    expect(screen.getByText(/Analyst Feedback & Model Score Drift Store/i)).toBeInTheDocument();

    // HTTP Attack Inspector Tab
    const httpTab = screen.getByText(/HTTP Attack Inspector/i);
    fireEvent.click(httpTab);
    expect(screen.getByText(/HTTP Request Payload & Web Attack Detector/i)).toBeInTheDocument();

    // Function & API Monitor Tab
    const funcTab = screen.getByText(/Function & API Monitor/i);
    fireEvent.click(funcTab);
    expect(screen.getByText(/Win32 API & System Call Event Monitor/i)).toBeInTheDocument();

    // API Explorer Tab
    const apiTab = screen.getByText(/API Explorer/i);
    fireEvent.click(apiTab);
    expect(screen.getByText(/FastAPI Endpoint Tester/i)).toBeInTheDocument();
  });

  it('allows submitting analyst feedback and triggering retraining pipeline', () => {
    render(<UrlInspector />);

    const feedbackTab = screen.getByText(/Feedback & Drift Store/i);
    fireEvent.click(feedbackTab);

    const retrainBtn = screen.getByText(/Trigger Retraining Pipeline/i);
    fireEvent.click(retrainBtn);

    expect(screen.getByText(/Model retrained successfully with updated analyst feedback/i)).toBeInTheDocument();
  });
});
