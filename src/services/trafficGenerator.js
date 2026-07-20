export const generateIP = () => {
  return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
};

export const generatePort = () => Math.floor(Math.random() * 65535);

const attackTypes = ['DDoS', 'Port Scan', 'SQL Injection', 'Malware C2'];

let forcedAttack = null;

export const triggerAttack = (attackType) => {
  forcedAttack = attackType;
  // Automatically clear forced attack after a few seconds
  setTimeout(() => {
    forcedAttack = null;
  }, 5000);
};

const mockGeo = ['RU', 'CN', 'US', 'BR', 'IR', 'KP'];
const mockPayloads = {
  'SQL Injection': ["' OR 1=1 --", "SELECT * FROM users;", "DROP TABLE admins;"],
  'Malware C2': ["GET /bot/cmd.exe", "POST /beacon/login", "User-Agent: CobaltStrike"],
  'Port Scan': ["SYN-Stealth", "Nmap Script Engine", "Connect() scan"],
  'DDoS': ["UDP Flood (Random junk)", "SYN Flood (Spoofed)", "HTTP GET Flood"],
  'Zero-Day': ["Encrypted Shellcode", "Unknown Buffer Overflow", "Heap Spray Pattern"]
};

export const generatePacket = () => {
  const isAttack = forcedAttack ? true : Math.random() > 0.95;
  const attackType = forcedAttack || (isAttack ? attackTypes[Math.floor(Math.random() * attackTypes.length)] : 'Normal');
  
  const packet = {
    id: Date.now() + Math.random().toString(36).substr(2, 9),
    timestamp: new Date().toLocaleTimeString('en-US', { hour12: false, fractionalSecondDigits: 3 }),
    srcIP: generateIP(),
    destIP: isAttack && (attackType === 'DDoS' || attackType === 'Port Scan') ? '192.168.1.100' : generateIP(),
    srcPort: generatePort(),
    destPort: isAttack && attackType === 'SQL Injection' ? 80 : generatePort(),
    protocol: Math.random() > 0.5 ? 'TCP' : 'UDP',
    size: isAttack && attackType === 'DDoS' ? Math.floor(Math.random() * 1500) + 1000 : Math.floor(Math.random() * 800) + 40,
    classification: attackType,
    threatScore: isAttack ? 75 + Math.random() * 25 : Math.random() * 20,
    geo: isAttack ? mockGeo[Math.floor(Math.random() * mockGeo.length)] : 'US',
    payloadInfo: isAttack && mockPayloads[attackType] 
      ? mockPayloads[attackType][Math.floor(Math.random() * mockPayloads[attackType].length)] 
      : 'Standard Network Flow'
  };

  return packet;
};
