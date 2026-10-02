import pptxgen from 'pptxgenjs';

async function buildPresentation() {
  const pres = new pptxgen();

  // Widescreen 16:9 layout
  pres.layout = 'LAYOUT_16x9';
  pres.title = 'AI-NIDS: Intelligent Network Intrusion Detection System';
  pres.author = 'AI-NIDS Development Team';

  // Light Theme Colors
  const BG_COLOR = 'F8FAFC';       // Crisp Slate-50 Background
  const CARD_BG = 'FFFFFF';        // Pure White Card Container
  const HEADER_COLOR = '0F172A';   // Deep Slate 900
  const TEXT_COLOR = '334155';     // Slate 700 Body Text
  const MUTED_COLOR = '64748B';    // Slate 500 Subtext
  const ACCENT_BLUE = '0284C7';    // Professional Sky / Cyber Blue
  const ACCENT_RED = 'DC2626';     // Clear Crimson Red
  const ACCENT_AMBER = 'D97706';   // Deep Amber / Warning
  const BORDER_COLOR = 'E2E8F0';   // Clean Slate 200 Border

  // Helper: Common Header
  function addHeader(slide, titleText, categoryText = 'AI-NIDS PROJECT PRESENTATION') {
    slide.addText(categoryText, {
      x: 0.8, y: 0.35, w: 11.5, h: 0.3,
      fontSize: 10, color: ACCENT_BLUE, bold: true, tracking: 2
    });
    slide.addText(titleText, {
      x: 0.8, y: 0.6, w: 11.5, h: 0.6,
      fontSize: 22, color: HEADER_COLOR, bold: true
    });
    slide.addShape(pres.ShapeType.line, {
      x: 0.8, y: 1.25, w: 11.7, h: 0,
      line: { color: BORDER_COLOR, width: 1.5 }
    });
  }

  // Helper: Common Background & Footer
  function setDarkBackground(slide) {
    slide.background = { color: BG_COLOR };
    slide.addShape(pres.ShapeType.line, {
      x: 0.8, y: 7.0, w: 11.7, h: 0,
      line: { color: BORDER_COLOR, width: 1 }
    });
    slide.addText('Intelligent Network Intrusion Detection System (AI-NIDS) | Academic Project Presentation', {
      x: 0.8, y: 7.05, w: 9.0, h: 0.3,
      fontSize: 9, color: MUTED_COLOR
    });
  }

  // ====================================================
  // SLIDE 1: Title Slide & Project Overview
  // ====================================================
  const slide1 = pres.addSlide();
  setDarkBackground(slide1);

  slide1.addShape(pres.ShapeType.roundRect, {
    x: 0.8, y: 1.5, w: 11.7, h: 5.0,
    rectRadius: 0.05,
    fill: { color: CARD_BG },
    line: { color: BORDER_COLOR, width: 2 }
  });

  slide1.addText('CYBERSECURITY & ARTIFICIAL INTELLIGENCE', {
    x: 1.2, y: 1.9, w: 10.0, h: 0.4,
    fontSize: 12, color: ACCENT_BLUE, bold: true, tracking: 3
  });

  slide1.addText('Intelligent Network Intrusion\nDetection System (AI-NIDS)', {
    x: 1.2, y: 2.4, w: 10.5, h: 1.5,
    fontSize: 32, color: HEADER_COLOR, bold: true, lineSpacing: 38
  });

  slide1.addText('A Hybrid Machine Learning Architecture for Real-Time Threat Detection & Automated SOC Operations', {
    x: 1.2, y: 4.1, w: 10.5, h: 0.6,
    fontSize: 15, color: TEXT_COLOR, italic: true
  });

  // Tech Badges
  const badges = ['React 19', 'FastAPI', 'Random Forest', 'Shannon Entropy', 'AWS Lambda', 'Docker'];
  badges.forEach((badge, idx) => {
    slide1.addShape(pres.ShapeType.roundRect, {
      x: 1.2 + idx * 1.75, y: 5.2, w: 1.55, h: 0.45,
      rectRadius: 0.2,
      fill: { color: 'F1F5F9' },
      line: { color: 'CBD5E1', width: 1 }
    });
    slide1.addText(badge, {
      x: 1.2 + idx * 1.75, y: 5.2, w: 1.55, h: 0.45,
      fontSize: 10, color: HEADER_COLOR, align: 'center', bold: true
    });
  });

  slide1.addNotes(
    "Good morning/afternoon everyone. Today, I am excited to present our project: the Intelligent Network Intrusion Detection System (AI-NIDS). " +
    "Modern networks face an unprecedented volume of cyber threats ranging from automated DDoS floods to zero-day malware. AI-NIDS combines machine learning " +
    "with real-time heuristic analysis inside a full-stack Security Operations Center dashboard."
  );

  // ====================================================
  // SLIDE 2: Abstract
  // ====================================================
  const slide2 = pres.addSlide();
  setDarkBackground(slide2);
  addHeader(slide2, 'Abstract: Project Overview & Core Findings');

  const abstractCards = [
    {
      title: 'The Research Challenge',
      accent: ACCENT_RED,
      items: [
        'Proliferation of connected devices expands network attack surfaces.',
        'Legacy signature NIDS (Snort, Suricata) fail against novel zero-day attacks.',
        'Obfuscated payloads & polymorphic malware bypass traditional firewalls.'
      ]
    },
    {
      title: 'Proposed AI-NIDS Solution',
      accent: HEADER_COLOR,
      items: [
        'Hybrid Machine Learning Engine combining Supervised & Unsupervised models.',
        'Random Forest Classifier (known vectors) + Shannon Entropy Engine (zero-days).',
        'Full-Stack SOC Dashboard built with React 19, Vite, and Recharts.'
      ]
    },
    {
      title: 'Key Results & Impact',
      accent: ACCENT_BLUE,
      items: [
        'Achieved >96.5% overall multi-class classification accuracy.',
        'Sub-3.2ms latency per flow vector ensures real-time packet inspection.',
        'Analyst feedback loop enables 1-click dynamic model retraining.'
      ]
    }
  ];

  abstractCards.forEach((card, idx) => {
    const xPos = 0.8 + idx * 4.0;
    slide2.addShape(pres.ShapeType.roundRect, {
      x: xPos, y: 1.6, w: 3.7, h: 5.0,
      rectRadius: 0.05,
      fill: { color: CARD_BG },
      line: { color: card.accent, width: 2 }
    });

    slide2.addText(card.title, {
      x: xPos + 0.3, y: 1.9, w: 3.1, h: 0.5,
      fontSize: 15, color: card.accent, bold: true
    });

    slide2.addText(card.items.map(item => `•  ${item}`).join('\n\n\n'), {
      x: xPos + 0.3, y: 2.6, w: 3.1, h: 3.8,
      fontSize: 12, color: TEXT_COLOR, lineSpacing: 18
    });
  });

  slide2.addNotes(
    "This slide provides our project Abstract. In summary, traditional Network Intrusion Detection Systems fail when facing novel attacks because they rely strictly on pre-recorded signatures. " +
    "In this work, we proposed and built AI-NIDS—a hybrid system combining Random Forest classification with Shannon Entropy randomness checks. It features a full-stack SOC web dashboard for live monitoring and automated incident response."
  );

  // ====================================================
  // SLIDE 3: Introduction & Project Objectives
  // ====================================================
  const slide3 = pres.addSlide();
  setDarkBackground(slide3);
  addHeader(slide3, 'Introduction & Core Project Objectives');

  const objBoxes = [
    { num: '01', title: 'Hybrid Detection Architecture', desc: 'Combine Supervised Random Forest Classifier (>95% target accuracy) with Unsupervised Shannon Entropy heuristic rules for zero-day threat detection.' },
    { num: '02', title: 'Multi-Vector Inspection', desc: 'Ingest and evaluate three core attack surfaces: Network Flow Packets, Phishing URLs/Domains, and Uploaded File & Log Payloads.' },
    { num: '03', title: 'Interactive SOC Web Dashboard', desc: 'Deliver a React 19 web application providing real-time telemetry charts (Recharts), live threat feeds, and 1-click firewall block controls.' },
    { num: '04', title: 'Continuous Analyst Feedback Loop', desc: 'Implement endpoints (/url/feedback) allowing security analysts to correct misclassifications and trigger 1-click dynamic model retraining.' }
  ];

  objBoxes.forEach((box, idx) => {
    const col = idx % 2;
    const row = Math.floor(idx / 2);
    const xPos = 0.8 + col * 6.0;
    const yPos = 1.6 + row * 2.6;

    slide3.addShape(pres.ShapeType.roundRect, {
      x: xPos, y: yPos, w: 5.6, h: 2.3,
      rectRadius: 0.05,
      fill: { color: CARD_BG },
      line: { color: BORDER_COLOR, width: 1.5 }
    });

    slide3.addText(box.num, {
      x: xPos + 0.3, y: yPos + 0.2, w: 1.0, h: 0.5,
      fontSize: 22, color: HEADER_COLOR, bold: true
    });

    slide3.addText(box.title, {
      x: xPos + 1.2, y: yPos + 0.2, w: 4.1, h: 0.4,
      fontSize: 15, color: ACCENT_BLUE, bold: true
    });

    slide3.addText(box.desc, {
      x: xPos + 1.2, y: yPos + 0.7, w: 4.1, h: 1.4,
      fontSize: 12, color: TEXT_COLOR, lineSpacing: 18
    });
  });

  slide3.addNotes(
    "Why did we build AI-NIDS? Modern cyber threats have evolved beyond simple port scans. Attackers hide behind Domain Generation Algorithms, obfuscate webshells in Base64, and launch high-volume DDoS floods. " +
    "Our vision for AI-NIDS was centered on four pillars: high accuracy, zero-day detection capability, multi-vector inspection, and an intuitive SOC dashboard."
  );

  // ====================================================
  // SLIDE 4: Literature Review & Comparative Analysis
  // ====================================================
  const slide4 = pres.addSlide();
  setDarkBackground(slide4);
  addHeader(slide4, 'Literature Review & Comparative Analysis');

  const litTableRows = [
    [
      { text: 'System Category', options: { bold: true, color: '0F172A', fill: 'F1F5F9' } },
      { text: 'Key Technology / Approach', options: { bold: true, color: '0F172A', fill: 'F1F5F9' } },
      { text: 'Strengths', options: { bold: true, color: '0F172A', fill: 'F1F5F9' } },
      { text: 'Critical Limitations', options: { bold: true, color: '0F172A', fill: 'F1F5F9' } }
    ],
    ['Legacy Signature NIDS', 'Snort, Suricata, YARA Rules', 'High processing speed for known signatures', 'Helpless against zero-day exploits; static rule database requiring manual updates.'],
    ['Traditional ML NIDS', 'Support Vector Machines, Naive Bayes', 'Learns non-linear boundary maps', 'High training latency on large flow logs; struggles with feature scaling & dimensionality.'],
    ['Deep Learning NIDS', 'LSTM Networks, 1D-CNN, Autoencoders', 'Excellent sequence modeling for flow patterns', 'Heavy compute requirement (>20ms latency); black-box model lacks interpretability.'],
    [
      { text: 'Proposed AI-NIDS', options: { bold: true, color: '0284C7', fill: 'F0F9FF' } },
      { text: 'Random Forest + Shannon Entropy', options: { bold: true, color: '0284C7', fill: 'F0F9FF' } },
      { text: '<3.2ms latency, high interpretability, zero-day protection', options: { bold: true, color: '0284C7', fill: 'F0F9FF' } },
      { text: 'Requires initial feature vectorization pipeline', options: { bold: true, color: '0284C7', fill: 'F0F9FF' } }
    ]
  ];

  slide4.addTable(litTableRows, {
    x: 0.8, y: 1.6, w: 11.7, h: 5.0,
    colW: [2.5, 3.0, 3.1, 3.1],
    border: { pt: 1, color: BORDER_COLOR },
    fill: CARD_BG,
    color: TEXT_COLOR,
    fontSize: 11,
    align: 'left'
  });

  slide4.addNotes(
    "In our Literature Review, we compared four major paradigms in network security. Legacy systems like Snort excel at known threats but fail completely against zero-day attacks. " +
    "Deep learning models like LSTM require expensive GPUs and suffer from high latency and black-box opacity. AI-NIDS pairs Random Forest with Shannon Entropy calculations, yielding low latency and high accuracy."
  );

  // ====================================================
  // SLIDE 5: System Modules & Architecture
  // ====================================================
  const slide5 = pres.addSlide();
  setDarkBackground(slide5);
  addHeader(slide5, 'System Modules & Functional Architecture');

  const modules = [
    { title: '1. Network Traffic Module', desc: 'Extracts telemetry vectors (ports, size, entropy, TCP flags). Feeds Random Forest classifier for multi-class threat scoring.', color: ACCENT_BLUE, x: 0.8, y: 1.6, w: 5.6, h: 2.3 },
    { title: '2. URL Intelligence Inspector', desc: 'Validates SSL certificates, raw IP hostnames, high-risk TLDs, and typosquatting distance. Calculates hostname entropy (>3.8) for DGA botnets.', color: HEADER_COLOR, x: 6.8, y: 1.6, w: 5.7, h: 2.3 },
    { title: '3. File & Payload Scanner', desc: 'Performs regex pattern checks for RCE, SQLi, and Obfuscated WebShells. Validates binary magic bytes and flags packed malware (>5.3 entropy).', color: ACCENT_RED, x: 0.8, y: 4.2, w: 5.6, h: 2.4 },
    { title: '4. Interactive SOC UI', desc: 'React 19 single-page application rendering live Recharts telemetry, filterable threat alerts feed, and an integrated Attack Simulator.', color: ACCENT_AMBER, x: 6.8, y: 4.2, w: 5.7, h: 2.4 }
  ];

  modules.forEach(mod => {
    slide5.addShape(pres.ShapeType.roundRect, {
      x: mod.x, y: mod.y, w: mod.w, h: mod.h,
      rectRadius: 0.05,
      fill: { color: CARD_BG },
      line: { color: mod.color, width: 2 }
    });

    slide5.addText(mod.title, {
      x: mod.x + 0.3, y: mod.y + 0.25, w: mod.w - 0.6, h: 0.4,
      fontSize: 15, color: mod.color, bold: true
    });

    slide5.addText(mod.desc, {
      x: mod.x + 0.3, y: mod.y + 0.75, w: mod.w - 0.6, h: 1.4,
      fontSize: 12, color: TEXT_COLOR, lineSpacing: 18
    });
  });

  slide5.addNotes(
    "Our application is divided into four integrated modules. The Network Traffic Module processes raw flow telemetry. The URL Inspector identifies phishing links and botnet DGA hostnames. " +
    "The File & Payload Scanner detects webshells, SQL injection, and executable masquerading. Finally, the SOC Dashboard ties these components together into a single interface."
  );

  // ====================================================
  // SLIDE 6: Software & Hardware Requirements
  // ====================================================
  const slide6 = pres.addSlide();
  setDarkBackground(slide6);
  addHeader(slide6, 'Software & Hardware Environment Requirements');

  // Left Side: Software Table
  slide6.addShape(pres.ShapeType.roundRect, {
    x: 0.8, y: 1.6, w: 5.6, h: 5.0,
    rectRadius: 0.05,
    fill: { color: CARD_BG },
    line: { color: ACCENT_BLUE, width: 2 }
  });

  slide6.addText('SOFTWARE STACK & DEPENDENCIES', {
    x: 1.1, y: 1.9, w: 5.0, h: 0.4,
    fontSize: 14, color: ACCENT_BLUE, bold: true
  });

  slide6.addText([
    '• Frontend: React 19, Vite, Tailwind CSS, Recharts',
    '• Backend API: Python 3.10+, FastAPI, Uvicorn',
    '• ML & Mathematics: Scikit-Learn, Pandas, NumPy',
    '• Database & Storage: PostgreSQL v14+, AWS S3',
    '• DevOps & Containerization: Docker, Docker Compose, Nginx Reverse Proxy, AWS Lambda (Dockerfile.lambda)'
  ].join('\n\n'), {
    x: 1.1, y: 2.4, w: 5.0, h: 3.9,
    fontSize: 12, color: TEXT_COLOR, lineSpacing: 18
  });

  // Right Side: Hardware Table
  slide6.addShape(pres.ShapeType.roundRect, {
    x: 6.8, y: 1.6, w: 5.7, h: 5.0,
    rectRadius: 0.05,
    fill: { color: CARD_BG },
    line: { color: HEADER_COLOR, width: 2 }
  });

  slide6.addText('HARDWARE SPECIFICATIONS', {
    x: 7.1, y: 1.9, w: 5.0, h: 0.4,
    fontSize: 14, color: HEADER_COLOR, bold: true
  });

  const hwRows = [
    [
      { text: 'Component', options: { bold: true, color: '0F172A', fill: 'F1F5F9' } },
      { text: 'Minimum Spec', options: { bold: true, color: '0F172A', fill: 'F1F5F9' } },
      { text: 'Recommended (SOC)', options: { bold: true, color: '0F172A', fill: 'F1F5F9' } }
    ],
    ['Processor (CPU)', '4-Core 2.5 GHz', '8-Core 3.5 GHz+'],
    ['Memory (RAM)', '8 GB DDR4', '16 GB - 32 GB DDR4/DDR5'],
    ['Storage', '20 GB SSD', '100 GB+ NVMe SSD'],
    ['Network Card', '1 Gbps NIC', '10 Gbps Dedicated NIC']
  ];

  slide6.addTable(hwRows, {
    x: 7.1, y: 2.4, w: 5.1, h: 3.9,
    colW: [1.7, 1.6, 1.8],
    border: { pt: 1, color: BORDER_COLOR },
    fill: CARD_BG,
    color: TEXT_COLOR,
    fontSize: 11,
    align: 'left'
  });

  slide6.addNotes(
    "Here are the hardware and software specifications for AI-NIDS. On the software side, we rely on React 19 and Vite for the frontend, FastAPI and Scikit-Learn for the backend, and Docker Compose for orchestration. " +
    "For hardware, minimum deployment requires a 4-core CPU with 8GB RAM, while production SOC environments benefit from an 8-core CPU, 16GB to 32GB RAM, and NVMe SSDs."
  );

  // ====================================================
  // SLIDE 7: Algorithm & Mathematical Formulations
  // ====================================================
  const slide7 = pres.addSlide();
  setDarkBackground(slide7);
  addHeader(slide7, 'Algorithm & Mathematical Formulations');

  // Left Column: Random Forest Algorithm
  slide7.addShape(pres.ShapeType.roundRect, {
    x: 0.8, y: 1.6, w: 5.6, h: 5.0,
    rectRadius: 0.05,
    fill: { color: CARD_BG },
    line: { color: ACCENT_BLUE, width: 2 }
  });

  slide7.addText('ALGORITHM 1: RANDOM FOREST CLASSIFIER', {
    x: 1.1, y: 1.9, w: 5.0, h: 0.4,
    fontSize: 13, color: ACCENT_BLUE, bold: true
  });

  slide7.addText([
    '1. Ingest normalized flow vector V = {src_port, dest_port, size, entropy, flags}.',
    '2. Evaluate vector across N=100 decision trees: y_b = T_b(V).',
    '3. Aggregate decision via Majority Voting:',
    '   Y_pred = mode( {y_1, y_2, ..., y_N} )',
    '4. Calculate Confidence Threat Score (0-100%):',
    '   Score = (Count of Malicious Votes / N) * 100%'
  ].join('\n\n'), {
    x: 1.1, y: 2.4, w: 5.0, h: 3.9,
    fontSize: 11, color: TEXT_COLOR, lineSpacing: 16
  });

  // Right Column: Shannon Entropy Formula & Thresholds
  slide7.addShape(pres.ShapeType.roundRect, {
    x: 6.8, y: 1.6, w: 5.7, h: 5.0,
    rectRadius: 0.05,
    fill: { color: CARD_BG },
    line: { color: ACCENT_RED, width: 2 }
  });

  slide7.addText('ALGORITHM 2: SHANNON ENTROPY ANOMALY ENGINE', {
    x: 7.1, y: 1.9, w: 5.0, h: 0.4,
    fontSize: 13, color: ACCENT_RED, bold: true
  });

  slide7.addText([
    'Mathematical Information Entropy Formula:',
    '   H(X) = - sum( P(x_i) * log2 P(x_i) )',
    '',
    'Multi-Stage Threshold Rules:',
    '• DGA Hostname Detection: Entropy > 3.8 flags pseudo-random botnet domains (e.g. x89qzk19mva.biz).',
    '• Packed File Detection: Binary Entropy > 5.3 flags encrypted malware droppers.',
    '• Zero-Day Defense: Detects unknown threats without signature database updates.'
  ].join('\n'), {
    x: 7.1, y: 2.4, w: 5.1, h: 3.9,
    fontSize: 11, color: TEXT_COLOR, lineSpacing: 16
  });

  slide7.addNotes(
    "This slide outlines our detection algorithms. Algorithm 1 is our Random Forest classifier. It takes normalized flow vectors and feeds them to 100 decision trees. " +
    "Algorithm 2 is our Shannon Entropy anomaly engine. By calculating the information entropy of domain names and binary payloads, we flag high randomness."
  );

  // ====================================================
  // SLIDE 8: System Screenshots & SOC UI Walkthrough
  // ====================================================
  const slide8 = pres.addSlide();
  setDarkBackground(slide8);
  addHeader(slide8, 'System Screenshots & SOC UI Walkthrough');

  // Big Dashboard Layout Card
  slide8.addShape(pres.ShapeType.roundRect, {
    x: 0.8, y: 1.6, w: 11.7, h: 5.0,
    rectRadius: 0.05,
    fill: { color: CARD_BG },
    line: { color: HEADER_COLOR, width: 2 }
  });

  slide8.addText('INTERACTIVE SECURITY OPERATIONS CENTER (SOC) DASHBOARD', {
    x: 1.1, y: 1.85, w: 11.0, h: 0.35,
    fontSize: 14, color: HEADER_COLOR, bold: true
  });

  const uiItems = [
    { title: 'Telemetry KPI Bar', desc: 'Live cards displaying Active Flows (1,420/s), Threat Ratio (4.2%), and Quarantined Payloads (18).', x: 1.1, y: 2.3, w: 5.5, h: 1.2, color: ACCENT_BLUE },
    { title: 'Recharts Telemetry Chart', desc: 'Real-time time-series visual rendering bandwidth usage spikes and attack volume distributions.', x: 6.8, y: 2.3, w: 5.3, h: 1.2, color: HEADER_COLOR },
    { title: 'Threat Feed Alert Table', desc: 'Filterable alert log showing origin IP badges, severity tags, and 1-click Firewall Block action buttons.', x: 1.1, y: 3.7, w: 5.5, h: 2.6, color: ACCENT_RED },
    { title: 'Live Attack Simulator Controls', desc: 'In-browser controls enabling analysts to inject synthetic DDoS, Port Scan, and SQLi attack vectors live.', x: 6.8, y: 3.7, w: 5.3, h: 2.6, color: ACCENT_AMBER }
  ];

  uiItems.forEach(item => {
    slide8.addShape(pres.ShapeType.roundRect, {
      x: item.x, y: item.y, w: item.w, h: item.h,
      rectRadius: 0.05,
      fill: { color: 'F8FAFC' },
      line: { color: item.color, width: 1.5 }
    });

    slide8.addText(item.title, {
      x: item.x + 0.2, y: item.y + 0.15, w: item.w - 0.4, h: 0.3,
      fontSize: 12, color: item.color, bold: true
    });

    slide8.addText(item.desc, {
      x: item.x + 0.2, y: item.y + 0.45, w: item.w - 0.4, h: item.h - 0.55,
      fontSize: 10, color: TEXT_COLOR
    });
  });

  slide8.addNotes(
    "Slide 8 demonstrates our Security Operations Center user interface. The dashboard features real-time telemetry metrics across the top, dynamic time-series charts powered by Recharts in the center, " +
    "and a live threat feed table at the bottom with one-click firewall blocking buttons. Analysts can also launch the integrated Attack Simulator to test model response."
  );

  // ====================================================
  // SLIDE 9: Experimental Evaluation & Model Performance
  // ====================================================
  const slide9 = pres.addSlide();
  setDarkBackground(slide9);
  addHeader(slide9, 'Experimental Evaluation & Performance Metrics');

  const evalTableRows = [
    [
      { text: 'Attack Category', options: { bold: true, color: '0F172A', fill: 'F1F5F9' } },
      { text: 'Precision', options: { bold: true, color: '0F172A', fill: 'F1F5F9' } },
      { text: 'Recall', options: { bold: true, color: '0F172A', fill: 'F1F5F9' } },
      { text: 'F1-Score', options: { bold: true, color: '0F172A', fill: 'F1F5F9' } },
      { text: 'Inference Latency', options: { bold: true, color: '0F172A', fill: 'F1F5F9' } }
    ],
    ['Normal Traffic', '98.4%', '99.1%', '98.7%', '< 2.0 ms'],
    ['DDoS Attack', '99.2%', '98.8%', '99.0%', '< 3.0 ms'],
    ['Port Scanning', '97.6%', '96.5%', '97.0%', '< 2.0 ms'],
    ['SQL Injection', '96.1%', '95.3%', '95.7%', '< 4.0 ms'],
    ['Zero-Day / DGA Anomaly', '93.8%', '91.2%', '92.5%', '< 5.0 ms'],
    [
      { text: 'Overall System Average', options: { bold: true, color: '0284C7', fill: 'F0F9FF' } },
      { text: '97.0%', options: { bold: true, color: '0284C7', fill: 'F0F9FF' } },
      { text: '96.2%', options: { bold: true, color: '0284C7', fill: 'F0F9FF' } },
      { text: '96.6%', options: { bold: true, color: '0284C7', fill: 'F0F9FF' } },
      { text: '< 3.2 ms', options: { bold: true, color: '0284C7', fill: 'F0F9FF' } }
    ]
  ];

  slide9.addTable(evalTableRows, {
    x: 0.8, y: 1.6, w: 11.7, h: 5.0,
    colW: [3.5, 2.0, 2.0, 2.0, 2.2],
    border: { pt: 1, color: BORDER_COLOR },
    fill: CARD_BG,
    color: TEXT_COLOR,
    fontSize: 12,
    align: 'center'
  });

  slide9.addNotes(
    "Here are our empirical evaluation results. Evaluated across synthetic network logs and simulated attack datasets, AI-NIDS achieved an overall precision of 97.0% and recall of 96.2%. " +
    "Crucially, total inference latency averaged under 3.2 milliseconds per flow packet, satisfying strict real-time monitoring requirements."
  );

  // ====================================================
  // SLIDE 10: Conclusion & Major Contributions
  // ====================================================
  const slide10 = pres.addSlide();
  setDarkBackground(slide10);
  addHeader(slide10, 'Conclusion & Major Project Contributions');

  const summaryItems = [
    { title: 'Hybrid Machine Learning Engine', desc: 'Successfully combined Supervised Random Forest classification with Unsupervised Shannon Entropy anomaly detection.', color: HEADER_COLOR },
    { title: 'Real-Time SOC Web Dashboard', desc: 'Built a full-stack React 19 web interface featuring live Recharts telemetry, threat log feeds, and 1-click firewall block controls.', color: ACCENT_BLUE },
    { title: 'Multi-Vector Security Inspection', desc: 'Unified flow packet telemetry, phishing URL inspection, and static file payload parsing into a single operational platform.', color: ACCENT_AMBER },
    { title: 'Scalable Cloud Deployment', desc: 'Packaged backend services into Docker Compose containers and AWS Lambda serverless functions (Dockerfile.lambda) for horizontal auto-scaling.', color: ACCENT_RED }
  ];

  summaryItems.forEach((item, idx) => {
    const col = idx % 2;
    const row = Math.floor(idx / 2);
    const xPos = 0.8 + col * 6.0;
    const yPos = 1.6 + row * 2.6;

    slide10.addShape(pres.ShapeType.roundRect, {
      x: xPos, y: yPos, w: 5.6, h: 2.3,
      rectRadius: 0.05,
      fill: { color: CARD_BG },
      line: { color: item.color, width: 2 }
    });

    slide10.addText(item.title, {
      x: xPos + 0.3, y: yPos + 0.2, w: 5.0, h: 0.4,
      fontSize: 15, color: item.color, bold: true
    });

    slide10.addText(item.desc, {
      x: xPos + 0.3, y: yPos + 0.7, w: 5.0, h: 1.4,
      fontSize: 12, color: TEXT_COLOR, lineSpacing: 18
    });
  });

  slide10.addNotes(
    "In conclusion, AI-NIDS demonstrates that combining machine learning classifiers with mathematical entropy checks provides a highly effective defense against modern cyber threats. " +
    "We have delivered a functional, production-ready full-stack application featuring a hybrid AI engine, an interactive SOC dashboard, and containerized cloud deployment capabilities."
  );

  // ====================================================
  // SLIDE 11: Future Scope & Feature Roadmap
  // ====================================================
  const slide11 = pres.addSlide();
  setDarkBackground(slide11);
  addHeader(slide11, 'Future Scope & Feature Roadmap');

  const roadmapCards = [
    { title: 'Deep Learning Integration', desc: 'Implementing Long Short-Term Memory (LSTM) networks and Autoencoders for temporal flow sequence anomaly detection.', color: ACCENT_BLUE },
    { title: 'Distributed Edge Sensors', desc: 'Deploying lightweight AI-NIDS probes across regional subnet routers feeding a central SIEM database lake.', color: HEADER_COLOR },
    { title: 'Automated SOAR Playbooks', desc: 'Generating dynamic BGP routing updates and active firewall blocking scripts automatically upon critical alert trigger.', color: ACCENT_AMBER },
    { title: 'Explainable AI (XAI)', desc: 'Incorporating SHAP values to provide security analysts with clear feature importance attribution for every flagged threat.', color: ACCENT_RED }
  ];

  roadmapCards.forEach((card, idx) => {
    const xPos = 0.8 + idx * 2.95;
    slide11.addShape(pres.ShapeType.roundRect, {
      x: xPos, y: 1.6, w: 2.75, h: 4.0,
      rectRadius: 0.05,
      fill: { color: CARD_BG },
      line: { color: card.color, width: 2 }
    });

    slide11.addText(card.title, {
      x: xPos + 0.2, y: 1.8, w: 2.35, h: 0.6,
      fontSize: 14, color: card.color, bold: true
    });

    slide11.addText(card.desc, {
      x: xPos + 0.2, y: 2.5, w: 2.35, h: 2.9,
      fontSize: 11, color: TEXT_COLOR, lineSpacing: 16
    });
  });

  // Thank You Banner
  slide11.addShape(pres.ShapeType.roundRect, {
    x: 0.8, y: 5.8, w: 11.7, h: 0.8,
    rectRadius: 0.05,
    fill: { color: 'F0F9FF' },
    line: { color: '0284C7', width: 1.5 }
  });

  slide11.addText('Thank You! Open for Questions & Academic Discussion.', {
    x: 0.8, y: 5.8, w: 11.7, h: 0.8,
    fontSize: 15, color: '0284C7', bold: true, align: 'center'
  });

  slide11.addNotes(
    "Looking ahead, our future roadmap includes three key developments: integrating LSTM neural networks for deep sequential pattern analysis, deploying distributed edge sensors across regional subnet routers, " +
    "and building automated SOAR playbooks for dynamic firewall and BGP route updates. Thank you for your attention, and I am now happy to answer any questions!"
  );

  // Write presentation file
  const fileName = 'AI_NIDS_Presentation.pptx';
  await pres.writeFile({ fileName });
  console.log(`Successfully generated PowerPoint presentation: ${fileName}`);
}

buildPresentation().catch(err => {
  console.error('Error generating presentation:', err);
  process.exit(1);
});
