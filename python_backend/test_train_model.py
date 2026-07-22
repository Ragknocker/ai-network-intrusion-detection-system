import unittest
import os
import joblib
from generate_dataset import generate_synthetic_dataset
from train_model import train_rf_model

class TestTrainModel(unittest.TestCase):

    def setUp(self):
        # Generate small dataset for quick test training
        generate_synthetic_dataset(num_samples=200)

    def tearDown(self):
        for filename in ["synthetic_network_traffic.csv", "rf_nids_model.pkl"]:
            if os.path.exists(filename):
                os.remove(filename)

    def test_train_rf_model_creates_pickle_artifact(self):
        train_rf_model()
        
        self.assertTrue(os.path.exists("rf_nids_model.pkl"))
        
        # Verify loaded model can predict
        clf = joblib.load("rf_nids_model.pkl")
        self.assertIsNotNone(clf)
        self.assertTrue(hasattr(clf, "predict"))

if __name__ == "__main__":
    unittest.main()
