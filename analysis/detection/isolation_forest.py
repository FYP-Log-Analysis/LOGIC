import json
from pathlib import Path

from sklearn.ensemble import IsolationForest

# Set up our file paths and detection parameters
INPUT_FILE = "../../data/features/baseline_features.json"
OUTPUT_FILE = "../../data/detection_results/isolation_forest_scores.json"

RANDOM_STATE = 42
CONTAMINATION = 0.1   # We're assuming about 10% of our data might be anomalous

# Helper functions

def load_features(file_path):
    """Load our feature data from the JSON file"""
    with open(file_path, "r") as file:
        return json.load(file)


# Feature matrix preparation

def build_feature_matrix(feature_rows):
    """
    Takes our feature data and builds a matrix that the ML algorithm can work with.
    We're only using the numerical features since that's what Isolation Forest expects.
    """
    matrix = []

    # Go through each time window and extract the numeric features
    for row in feature_rows:
        # Build a feature vector with all our numeric measurements
        vector = [
            row["event_count"],
            row["process_event_count"],
            row["unique_process_count"],
            row["unique_parent_process_count"],
            row["unique_user_count"],
            row["unique_computer_count"],
            row["system32_exec_count"],
            row["non_system_exec_count"],
            row["registry_event_count"],
            row["avg_chain_depth"],
            row["max_chain_depth"],
            row["self_parent_count"],
            row["repeated_process_count"],
            row["process_entropy"],
            row["core_process_ratio"],
            row["non_core_process_count"]
        ]

        matrix.append(vector)

    return matrix


# The main anomaly detection logic

def run_isolation_forest(feature_matrix):
    """Run the actual anomaly detection using Isolation Forest"""
    # Set up the model with 100 trees - more trees = more stable results
    model = IsolationForest(
        n_estimators=100,
        contamination=CONTAMINATION,
        random_state=RANDOM_STATE
    )

    # Train the model on our data
    model.fit(feature_matrix)

    # Get anomaly scores (higher = more normal, lower = more suspicious)
    anomaly_scores = model.decision_function(feature_matrix)
    # Get binary predictions (-1 = anomaly, 1 = normal)
    anomaly_labels = model.predict(feature_matrix)

    return anomaly_scores, anomaly_labels


# Save our findings to a file

def save_results(windows, scores, labels, output_path):
    """Package up our results in a nice JSON format"""
    results = []

    # Combine the original window data with our anomaly scores
    for i in range(len(windows)):
        results.append({
            "window_start": windows[i]["window_start"],
            "window_end": windows[i]["window_end"],
            "anomaly_score": float(scores[i]),  # Convert numpy float to regular float
            "is_anomalous": True if labels[i] == -1 else False  # -1 means anomaly
        })

    with open(output_path, "w") as file:
        json.dump(results, file, indent=2)


# Main program flow

def main():
    """Main function that ties everything together"""
    # Figure out where our files are relative to this script
    base_path = Path(__file__).parent

    input_path = base_path / INPUT_FILE
    output_path = base_path / OUTPUT_FILE

    print("Loading feature data...")
    feature_rows = load_features(input_path)

    print("Preparing feature matrix...")
    feature_matrix = build_feature_matrix(feature_rows)

    print("Running Isolation Forest...")
    scores, labels = run_isolation_forest(feature_matrix)

    print("Saving results...")
    save_results(feature_rows, scores, labels, output_path)

    print("\nDone! Isolation Forest analysis completed.")
    print(f"Results saved to: {output_path}")


if __name__ == "__main__":
    main()
