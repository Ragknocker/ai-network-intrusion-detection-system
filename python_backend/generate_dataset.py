import pandas as pd
import numpy as np
import random
import uuid
import time

def generate_synthetic_dataset(num_samples=10000):
    print(f"Generating {num_samples} synthetic network flow records...")
    
    data = []
    attack_types = ['DDoS', 'Port Scan', 'SQL Injection', 'Malware C2', 'Zero-Day']
    
    for _ in range(num_samples):
        is_attack = random.random() > 0.8
        classification = random.choice(attack_types) if is_attack else 'Normal'
        
        # Synthetic features
        protocol = random.choice(['TCP', 'UDP', 'ICMP'])
        src_port = random.randint(1024, 65535)
        dest_port = 80 if classification == 'SQL Injection' else random.randint(1, 65535)
        
        if classification == 'DDoS':
            size = random.randint(1000, 1500)
            entropy = random.uniform(0.1, 0.3)
            flags_syn = 1
        elif classification == 'Port Scan':
            size = random.randint(40, 100)
            entropy = random.uniform(0.8, 0.9)
            flags_syn = 1
        else:
            size = random.randint(40, 800)
            entropy = random.uniform(0.3, 0.7)
            flags_syn = random.choice([0, 1])

        record = {
            'id': str(uuid.uuid4()),
            'timestamp': time.time(),
            'src_ip': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            'dest_ip': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            'src_port': src_port,
            'dest_port': dest_port,
            'protocol': protocol,
            'size': size,
            'entropy': entropy,
            'flags_syn': flags_syn,
            'classification': classification,
            'label': 1 if is_attack else 0
        }
        data.append(record)
        
    df = pd.DataFrame(data)
    df.to_csv("synthetic_network_traffic.csv", index=False)
    print("Dataset saved to synthetic_network_traffic.csv")

if __name__ == "__main__":
    generate_synthetic_dataset()
