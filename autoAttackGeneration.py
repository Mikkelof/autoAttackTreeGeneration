import os
import csv
import requests
import json
import re
from collections import defaultdict

class Node:
    def __init__(self, originalBody="", actionableBody=""):
        self.originalBody = originalBody
        self.actionableBody = actionableBody

def parse_execution_flow(execution_flow):
    instructionsSummarize = (
        "Rewrite the text as one concise, actionable sentence. Do not include any bullet points, numbered steps, markdown, or extra information — only a single sentence. "
        "You should NOT add anything, such as further instructions or additional information, to the text."
    )
    
    steps = execution_flow.split('::STEP:')[1:]
    objectives = []
    
    for step_idx, step in enumerate(steps, 1):
        objective = None
        objective_title = ""
        
        if 'DESCRIPTION:[' in step:
            start = step.index('DESCRIPTION:[') + len('DESCRIPTION:[')
            end = step.index(']', start)
            objective_title = step[start:end].strip()
            objective = f"[{objective_title}]"
        elif 'DESCRIPTION:' in step:
            start = step.index('DESCRIPTION:') + len('DESCRIPTION:')
            end = step.find('::', start)
            if end == -1:
                end = len(step)
            objective_title = step[start:end].strip()
            objective = f"[Step {step_idx}] {objective_title}"
        
        if not objective and 'PHASE:' in step:
            phase_start = step.index('PHASE:') + len('PHASE:')
            phase_end = step.find(':', phase_start)
            phase = step[phase_start:phase_end].strip() if phase_end != -1 else "Unknown"
            objective = f"[{phase} Phase]"
        
        if not objective:
            objective = f"[Step {step_idx}]"

        # Extract methods
        methods = []
        technique_parts = step.split('TECHNIQUE:')[1:]
        for tech in technique_parts:
            method = tech.split('::', 1)[0].strip()
            if method:
                actionable_method = callGPT(instructionsSummarize, method)
                methods.append(Node(method, actionable_method))
        
        objectives.append((objective, methods))
    
    return objectives

def parse_related_patterns(related_patterns, capec_dir):
    child_nodes = []
    entries = related_patterns.split('::')
    for entry in entries:
        parts = entry.split(':')
        if len(parts) >= 4 and parts[0] == 'NATURE' and parts[1] in ['CanFollow']:
            if include_capec(parts[3], capec_dir):
                child_nodes.append(f"CAPEC-{parts[3]}")
    return child_nodes

def include_capec(capec_id, capec_dir):
    capec_file = os.path.join(capec_dir, f"capec_{capec_id}.csv")
    if os.path.exists(capec_file):
        with open(capec_file, newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                abstraction = row['Abstraction']
                if abstraction in ('Standard', 'Detailed'):
                    return True
    return False

def build_attack_tree(name, capec_id, execution_flow_data, count):
    duplicate_note = " (duplicate)" if count > 1 else ""
    tree = [f"{name} (CAPEC-{capec_id}){duplicate_note}"]
    
    for obj_idx, (objective, methods) in enumerate(execution_flow_data):
        obj_prefix = '└─' if obj_idx == len(execution_flow_data) - 1 else '├─'
        tree.append(f"{obj_prefix} Attack Objective: {objective}")
        indent = '   ' if obj_prefix == '└─' else '│  '
        
        for method_idx, method in enumerate(methods):
            m_prefix = '└─' if method_idx == len(methods) - 1 else '├─'
            tree.append(f"{indent}{m_prefix} Attack Method: {method.actionableBody}")
    
    return tree

def process_capec(capec_id, capec_dir, current_path=None, duplicates=None):
    if current_path is None:
        current_path = []
    if duplicates is None:
        duplicates = defaultdict(int)
    
    if capec_id in current_path:
        return []
    
    duplicates[capec_id] += 1
    
    capec_file = os.path.join(capec_dir, f"capec_{capec_id}.csv")
    if not os.path.exists(capec_file):
        print(f"CAPEC-{capec_id} file not found.")
        return []
    
    with open(capec_file, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            execution_flow_data = parse_execution_flow(row['Execution Flow'])
            child_nodes = parse_related_patterns(row['Related Attack Patterns'], capec_dir)
            current_lines = build_attack_tree(row['Name'], capec_id, execution_flow_data, duplicates[capec_id])
            
            if child_nodes:
                current_lines.append("└─ Child Nodes:")
                for i, child in enumerate(child_nodes):
                    child_id = child.split('-')[1]
                    child_sub_lines = process_capec(child_id, capec_dir, current_path + [capec_id], duplicates)
                    if not child_sub_lines:
                        continue
                    
                    if i == len(child_nodes) - 1:
                        connector = '   └─ '
                        indent = '    '
                    else:
                        connector = '   ├─ '
                        indent = '   │  '
                    
                    current_lines.append(connector + child_sub_lines[0])
                    for line in child_sub_lines[1:]:
                        current_lines.append(indent + line)
            
            return current_lines
    
    return []

def callGPT(instructions, originalText):
    url = 'http://localhost:1234/v1/chat/completions'
    headers = {"Content-Type": "application/json"}
    data = {
        "model": "deepseek-r1-distill-qwen-7b",
        "messages": [
            {"role": "system", "content": instructions},
            {"role": "user", "content": originalText}
        ],
        "temperature": 0.7,
        "max_tokens": -1,
        "stream": False
    }

    response = requests.post(url, headers=headers, data=json.dumps(data))

    if response.status_code == 200:
        response_json = response.json()
        full_content = response_json["choices"][0]["message"]["content"]
        extracted_content = re.sub(r".*</think>\s*", "", full_content, flags=re.DOTALL)
        return extracted_content.strip()
    else:
        print(f"Error: {response.status_code}, {response.text}")
        return ""

if __name__ == "__main__":
    capec_id = "653"
    capec_dir = "./capec_data/"
    duplicates = defaultdict(int)
    attack_tree_lines = process_capec(capec_id, capec_dir, duplicates=duplicates)
    
    print('\n'.join(attack_tree_lines))
    print("\nDuplicate Nodes Report:")
    for capec_id, count in duplicates.items():
        if count > 1:
            print(f"- CAPEC-{capec_id} appears {count} times in the tree")