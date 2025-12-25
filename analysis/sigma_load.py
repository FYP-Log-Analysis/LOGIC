import os
import yaml

# Loads all Sigma rules from a folder (YAML files)
def load_sigma_rules(rules_folder):
    rules = []  # List to store rules
    # Go through every file in the folder and subfolders
    for folder, subfolders, files in os.walk(rules_folder):
        for filename in files:
            # Only look at .yml files
            if filename.endswith('.yml'):
                file_path = os.path.join(folder, filename)
                try:
                    # Open and read the YAML file
                    with open(file_path, 'r', encoding='utf-8') as f:
                        rule = yaml.safe_load(f)
                        rule['source_file'] = file_path  # Save file path
                        rules.append(rule)
                except Exception as e:
                    # Print error but keep going
                    print('Could not load rule:', file_path, e)
    return rules  # Return all loaded rules
