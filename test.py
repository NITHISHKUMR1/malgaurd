import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
import warnings
warnings.filterwarnings('ignore')

# Set random seed for reproducibility
np.random.seed(42)
random.seed(42)

# Define malware families and their characteristics
malware_families = {
    'Ransomware': {
        'description': 'Encrypts files and demands ransom',
        'patterns': ['high_encryption', 'file_modifications', 'bitcoin_addresses', 'registry_persistence'],
        'severity': 'Critical'
    },
    'Trojan': {
        'description': 'Disguised as legitimate software',
        'patterns': ['stealth_behavior', 'keylogging', 'backdoor_connections', 'credential_theft'],
        'severity': 'High'
    },
    'Worm': {
        'description': 'Self-replicating malware',
        'patterns': ['network_spreading', 'email_propagation', 'high_network_activity', 'exploit_usage'],
        'severity': 'High'
    },
    'Spyware': {
        'description': 'Steals user data',
        'patterns': ['data_harvesting', 'screen_capturing', 'browser_monitoring', 'keystroke_logging'],
        'severity': 'Medium'
    },
    'Adware': {
        'description': 'Displays unwanted advertisements',
        'patterns': ['popup_generation', 'browser_redirects', 'ad_click_fraud', 'tracking_cookies'],
        'severity': 'Low'
    },
    'Rootkit': {
        'description': 'Hides malicious activities',
        'patterns': ['kernel_modification', 'process_hiding', 'file_hiding', 'registry_hiding'],
        'severity': 'Critical'
    },
    'Keylogger': {
        'description': 'Records keystrokes',
        'patterns': ['keyboard_hooking', 'clipboard_monitoring', 'log_exfiltration', 'stealth_installation'],
        'severity': 'High'
    },
    'Backdoor': {
        'description': 'Remote access malware',
        'patterns': ['remote_connections', 'command_control', 'persistent_access', 'firewall_disable'],
        'severity': 'Critical'
    },
    'Cryptominer': {
        'description': 'Uses system resources for mining',
        'patterns': ['high_cpu_usage', 'crypto_addresses', 'mining_processes', 'persistent_execution'],
        'severity': 'Medium'
    },
    'Banking_Trojan': {
        'description': 'Steals banking credentials',
        'patterns': ['browser_injection', 'form_grabbing', 'sms_interception', 'banking_app_targeting'],
        'severity': 'Critical'
    }
}

def safe_random_int(low, high):
    """Safely generate random integer with bounds checking"""
    if high <= low:
        return low
    return int(np.random.randint(low, high))

def create_malware_dataset(n_samples=10000):
    """
    Create a comprehensive dataset with different malware types
    """
    
    print(f"Generating {n_samples} samples...")
    
    # Pre-allocate lists with known size for better performance
    data = {key: [None] * n_samples for key in [
        'file_id', 'file_name', 'file_type', 'file_size_bytes', 'entropy',
        'pe_features', 'section_count', 'imports_count', 'exports_count',
        'api_calls_count', 'suspicious_api_calls', 'network_connections',
        'unique_ips', 'dns_requests', 'registry_changes', 'file_operations',
        'process_injections', 'code_obfuscation', 'packer_detected',
        'anti_debug_techniques', 'vm_detection', 'encryption_usage',
        'cpu_usage_percent', 'memory_usage_mb', 'persistence_mechanisms',
        'command_control_channels', 'data_exfiltration', 'privilege_escalation',
        'signature_valid', 'malware_family', 'severity', 'detection_score'
    ]}
    
    # File types distribution
    file_types = ['exe', 'dll', 'scr', 'sys', 'com', 'bat', 'ps1', 'vbs', 'js', 'msi']
    
    for i in range(n_samples):
        # Determine if sample is malware or benign (70% malware, 30% benign for diversity)
        is_malware = np.random.random() < 0.7
        
        if is_malware:
            # Select malware family
            malware_family = random.choice(list(malware_families.keys()))
            severity = malware_families[malware_family]['severity']
            
            # Generate features based on malware family
            if malware_family == 'Ransomware':
                entropy = np.random.uniform(7.5, 8.5)
                api_calls = np.random.randint(500, 2000)
                suspicious_api = np.random.randint(100, 500)
                network_conn = np.random.randint(10, 50)
                registry_changes = np.random.randint(50, 200)
                file_ops = np.random.randint(1000, 5000)
                encryption = 1
                cpu_usage = np.random.uniform(30, 90)
                memory_usage = np.random.uniform(200, 800)
                
            elif malware_family == 'Trojan':
                entropy = np.random.uniform(6.5, 7.8)
                api_calls = np.random.randint(300, 1500)
                suspicious_api = np.random.randint(50, 300)
                network_conn = np.random.randint(20, 100)
                registry_changes = np.random.randint(20, 100)
                file_ops = np.random.randint(50, 300)
                encryption = np.random.choice([0, 1], p=[0.7, 0.3])
                cpu_usage = np.random.uniform(10, 50)
                memory_usage = np.random.uniform(100, 400)
                
            elif malware_family == 'Worm':
                entropy = np.random.uniform(6.0, 7.5)
                api_calls = np.random.randint(200, 1000)
                suspicious_api = np.random.randint(30, 200)
                network_conn = np.random.randint(100, 500)
                registry_changes = np.random.randint(10, 50)
                file_ops = np.random.randint(100, 500)
                encryption = 0
                cpu_usage = np.random.uniform(20, 70)
                memory_usage = np.random.uniform(80, 300)
                
            elif malware_family == 'Spyware':
                entropy = np.random.uniform(5.5, 7.0)
                api_calls = np.random.randint(150, 800)
                suspicious_api = np.random.randint(20, 150)
                network_conn = np.random.randint(10, 200)
                registry_changes = np.random.randint(5, 50)
                file_ops = np.random.randint(20, 200)
                encryption = np.random.choice([0, 1], p=[0.8, 0.2])
                cpu_usage = np.random.uniform(5, 30)
                memory_usage = np.random.uniform(50, 200)
                
            elif malware_family == 'Cryptominer':
                entropy = np.random.uniform(4.5, 6.5)
                api_calls = np.random.randint(100, 500)
                suspicious_api = np.random.randint(10, 100)
                network_conn = np.random.randint(5, 30)
                registry_changes = np.random.randint(10, 100)
                file_ops = np.random.randint(10, 100)
                encryption = 0
                cpu_usage = np.random.uniform(70, 100)  # Very high CPU usage
                memory_usage = np.random.uniform(50, 300)
                
            else:  # Other malware families
                entropy = np.random.uniform(5.0, 7.5)
                api_calls = np.random.randint(100, 1000)
                suspicious_api = np.random.randint(10, 200)
                network_conn = np.random.randint(5, 150)
                registry_changes = np.random.randint(5, 100)
                file_ops = np.random.randint(10, 500)
                encryption = np.random.choice([0, 1], p=[0.9, 0.1])
                cpu_usage = np.random.uniform(10, 60)
                memory_usage = np.random.uniform(50, 500)
            
            # Common malware characteristics
            code_obfuscation = np.random.choice([0, 1], p=[0.4, 0.6])
            packer = np.random.choice([0, 1], p=[0.5, 0.5])
            anti_debug = np.random.choice([0, 1], p=[0.6, 0.4])
            persistence = np.random.choice([0, 1, 2], p=[0.3, 0.4, 0.3])
            privilege_esc = np.random.choice([0, 1], p=[0.7, 0.3])
            data_exfil = np.random.choice([0, 1], p=[0.5, 0.5])
            
        else:
            # Benign software characteristics
            malware_family = 'Benign'
            severity = 'None'
            entropy = np.random.uniform(3.0, 5.5)
            api_calls = np.random.randint(20, 300)
            suspicious_api = np.random.randint(0, 20)
            network_conn = np.random.randint(0, 10)
            registry_changes = np.random.randint(0, 20)
            file_ops = np.random.randint(0, 50)
            encryption = 0
            cpu_usage = np.random.uniform(0, 20)
            memory_usage = np.random.uniform(20, 150)
            code_obfuscation = 0
            packer = 0
            anti_debug = 0
            persistence = 0
            privilege_esc = 0
            data_exfil = 0
        
        # Calculate derived values with bounds checking
        unique_ips = safe_random_int(0, max(1, network_conn))
        dns_requests = safe_random_int(0, max(1, network_conn // 2 + 1))
        command_control = safe_random_int(0, 5) if is_malware else 0
        process_injection = np.random.choice([0, 1], p=[0.8, 0.2]) if is_malware else 0
        vm_detection = np.random.choice([0, 1], p=[0.9, 0.1]) if is_malware else 0
        
        # Calculate detection score based on malicious indicators
        detection_score = (
            (entropy > 6.5) * 0.15 +
            (api_calls > 300) * 0.10 +
            (suspicious_api > 50) * 0.15 +
            (network_conn > 20) * 0.10 +
            (registry_changes > 30) * 0.10 +
            (file_ops > 100) * 0.10 +
            encryption * 0.10 +
            code_obfuscation * 0.05 +
            packer * 0.05 +
            anti_debug * 0.05 +
            (persistence > 0) * 0.05
        )
        
        # Add some randomness
        detection_score += np.random.normal(0, 0.05)
        detection_score = np.clip(detection_score, 0, 1)
        
        # Add data to dictionary
        data['file_id'][i] = f'FILE_{i:06d}'
        data['file_name'][i] = f'sample_{i}.{random.choice(file_types)}'
        data['file_type'][i] = random.choice(file_types)
        data['file_size_bytes'][i] = int(np.random.exponential(500000))
        data['entropy'][i] = entropy
        data['pe_features'][i] = np.random.randint(10, 50)
        data['section_count'][i] = np.random.randint(3, 12)
        data['imports_count'][i] = np.random.randint(10, 200)
        data['exports_count'][i] = np.random.randint(0, 50)
        data['api_calls_count'][i] = api_calls
        data['suspicious_api_calls'][i] = suspicious_api
        data['network_connections'][i] = network_conn
        data['unique_ips'][i] = unique_ips
        data['dns_requests'][i] = dns_requests
        data['registry_changes'][i] = registry_changes
        data['file_operations'][i] = file_ops
        data['process_injections'][i] = process_injection
        data['code_obfuscation'][i] = code_obfuscation
        data['packer_detected'][i] = packer
        data['anti_debug_techniques'][i] = anti_debug
        data['vm_detection'][i] = vm_detection
        data['encryption_usage'][i] = encryption
        data['cpu_usage_percent'][i] = cpu_usage
        data['memory_usage_mb'][i] = memory_usage
        data['persistence_mechanisms'][i] = persistence
        data['command_control_channels'][i] = command_control
        data['data_exfiltration'][i] = data_exfil
        data['privilege_escalation'][i] = privilege_esc
        data['signature_valid'][i] = 0 if is_malware else np.random.choice([0, 1], p=[0.2, 0.8])
        data['malware_family'][i] = malware_family
        data['severity'][i] = severity
        data['detection_score'][i] = detection_score
        
        # Progress indicator
        if (i + 1) % 1000 == 0:
            print(f"Generated {i + 1}/{n_samples} samples...")
    
    # Create DataFrame
    df = pd.DataFrame(data)
    
    # Add timestamp for time-based analysis (fixed the TypeError)
    print("Adding temporal features...")
    start_date = datetime(2023, 1, 1)
    # Convert numpy integers to Python integers
    random_days = np.random.randint(0, 365, n_samples)
    date_range = [start_date + timedelta(days=int(day)) for day in random_days]
    df['detection_date'] = date_range
    
    return df

# Create the dataset
print("="*60)
print("CREATING COMPREHENSIVE MALWARE DATASET")
print("="*60)
print("\nThis dataset will include:")
print(f"- {len(malware_families)} different malware families")
print("- Benign software samples")
print("- 30+ behavioral features")
print("- Detection scores for training")
print("- Temporal features for time-based analysis")
print("\nStarting generation...\n")

df = create_malware_dataset(n_samples=10000)

# Display dataset information
print(f"\n{'='*60}")
print("DATASET CREATION COMPLETE!")
print(f"{'='*60}")
print(f"\n✅ Dataset Shape: {df.shape}")
print(f"✅ Total Features: {len(df.columns)}")
print(f"✅ Total Samples: {len(df)}")

# Display malware family distribution
print(f"\n{'='*60}")
print("MALWARE FAMILY DISTRIBUTION")
print(f"{'='*60}")
family_dist = df['malware_family'].value_counts()
for family, count in family_dist.items():
    percentage = (count / len(df)) * 100
    bar = '█' * int(percentage / 2)
    print(f"{family:20s}: {count:5d} ({percentage:5.2f}%) {bar}")

# Display severity distribution
print(f"\n{'='*60}")
print("SEVERITY DISTRIBUTION (Malware Only)")
print(f"{'='*60}")
malware_df = df[df['malware_family'] != 'Benign']
severity_dist = malware_df['severity'].value_counts()
for severity, count in severity_dist.items():
    percentage = (count / len(malware_df)) * 100
    bar = '█' * int(percentage / 2)
    print(f"{severity:10s}: {count:5d} ({percentage:5.2f}%) {bar}")

# Display statistics for each malware type
print(f"\n{'='*60}")
print("CHARACTERISTICS BY MALWARE TYPE")
print(f"{'='*60}")
stats_data = []
for family in malware_families.keys():
    family_data = df[df['malware_family'] == family]
    if len(family_data) > 0:
        stats_data.append({
            'Family': family,
            'Samples': len(family_data),
            'Avg Entropy': f"{family_data['entropy'].mean():.2f}",
            'Avg API Calls': f"{family_data['api_calls_count'].mean():.0f}",
            'Avg Network': f"{family_data['network_connections'].mean():.0f}",
            'Avg CPU %': f"{family_data['cpu_usage_percent'].mean():.1f}",
            'Detection Score': f"{family_data['detection_score'].mean():.3f}"
        })

stats_df = pd.DataFrame(stats_data)
print(stats_df.to_string(index=False))

# Save the dataset
print(f"\n{'='*60}")
print("SAVING DATASET")
print(f"{'='*60}")
df.to_csv('malware_dataset_multitype.csv', index=False)
print(f"✅ Dataset saved as 'malware_dataset_multitype.csv'")

# Display sample of the dataset
print(f"\n{'='*60}")
print("SAMPLE DATA (First 5 rows)")
print(f"{'='*60}")
pd.set_option('display.max_columns', None)
pd.set_option('display.width', None)
print(df.head())

# Display dataset information
print(f"\n{'='*60}")
print("DATASET INFORMATION")
print(f"{'='*60}")
print(f"\nData Types:")
print(df.dtypes.value_counts())
print(f"\nMissing Values: {df.isnull().sum().sum()}")

print(f"\n{'='*60}")
print("✅ DATASET READY FOR ANN MODEL TRAINING!")
print(f"{'='*60}")
print("\nYou can now use this dataset for:")
print("1. Malware classification (multi-class)")
print("2. Malware detection (binary)")
print("3. Severity prediction")
print("4. Behavioral analysis")
print("5. Time-series malware analysis")