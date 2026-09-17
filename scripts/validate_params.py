import json
import yaml
import sys
import argparse

def validate(template_path, json_path):
    # Load template
    with open(template_path, 'r') as f:
        # Some CFN tags like !Sub might break pyyaml, use SafeLoader or ignore tags
        yaml.SafeLoader.add_multi_constructor('!', lambda loader, suffix, node: None)
        template = yaml.safe_load(f)
    
    # Load json
    with open(json_path, 'r') as f:
        data = json.load(f)
        
    expected_params = set(template.get('Parameters', {}).keys())
    provided_params = set(data.get('Parameters', {}).keys())
    
    missing = expected_params - provided_params
    extra = provided_params - expected_params
    
    success = True
    if missing:
        print(f"ERROR: Missing parameters in JSON: {missing}", file=sys.stderr)
        success = False
    
    if extra:
        print(f"WARNING: Extra parameters in JSON not in template: {extra}", file=sys.stderr)
    
    if not success:
        sys.exit(1)
    
    print("Validation successful: All template parameters are present in the JSON.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--template', required=True)
    parser.add_argument('--json', required=True)
    args = parser.parse_args()
    validate(args.template, args.json)
