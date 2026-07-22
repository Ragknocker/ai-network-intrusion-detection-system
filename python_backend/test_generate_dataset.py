import unittest
import os
import pandas as pd
from generate_dataset import generate_synthetic_dataset

class TestGenerateDataset(unittest.TestCase):
    TEST_CSV = "test_synthetic_network_traffic.csv"

    def setUp(self):
        # Override output file for testing if necessary, or test synthetic generation
        pass

    def tearDown(self):
        if os.path.exists(self.TEST_CSV):
            os.remove(self.TEST_CSV)
        if os.path.exists("synthetic_network_traffic.csv"):
            os.remove("synthetic_network_traffic.csv")

    def test_generate_synthetic_dataset_sample_count_and_schema(self):
        num_samples = 100
        generate_synthetic_dataset(num_samples=num_samples)
        
        self.assertTrue(os.path.exists("synthetic_network_traffic.csv"))
        df = pd.read_csv("synthetic_network_traffic.csv")
        
        # Verify row count
        self.assertEqual(len(df), num_samples)
        
        # Verify required columns
        expected_columns = {
            'id', 'timestamp', 'src_ip', 'dest_ip', 'src_port', 
            'dest_port', 'protocol', 'size', 'entropy', 'flags_syn', 
            'classification', 'label'
        }
        self.assertTrue(expected_columns.issubset(set(df.columns)))

        # Verify no nulls
        self.assertEqual(df.isnull().sum().sum(), 0)

        # Verify protocols
        self.assertTrue(set(df['protocol'].unique()).issubset({'TCP', 'UDP', 'ICMP'}))

        # Verify binary labels (0 or 1)
        self.assertTrue(set(df['label'].unique()).issubset({0, 1}))

if __name__ == "__main__":
    unittest.main()
