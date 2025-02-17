import os
import csv
import requests
import json
import re

class Node:
    def __init__(self, originalBody="", actionableBody=""):
        self.originalBody = originalBody
        self.actionableBody = actionableBody

def parse_execution_flow(execution_flow):
    instructionsSummarize = (
        "Rewrite the text as a super short, actionable step. "
        "You should NOT add anything, such as further instructions or additional information, to the text. "
        "It should only be text, no markdown, code, lists or anything like that."
    )
    
    steps = execution_flow.split('::STEP:')[1:]
    objectives = []
    
    for step in steps:
        if 'DESCRIPTION:[' in step:
            start = step.index('DESCRIPTION:[') + len('DESCRIPTION:[')
            end = step.index(']', start)
            objective_title = step[start:end].strip()
            objective = f"[{objective_title}]"
        else:
            objective = None

        methods = []
        technique_parts = step.split('TECHNIQUE:')[1:]
        for tech in technique_parts:
            method = tech.split('::', 1)[0].strip()
            if method:
                actionable_method = callGPT(instructionsSummarize, method)
                methods.append(Node(method, actionable_method))
        
        if objective:
            objectives.append((objective, methods))
    
    return objectives

def parse_related_patterns(related_patterns):
    child_nodes = []
    entries = related_patterns.split('::')
    for entry in entries:
        parts = entry.split(':')
        if len(parts) >= 4 and parts[0] == 'NATURE' and parts[1] in ['CanFollow', 'ChildOf']:
            child_nodes.append(f"CAPEC-{parts[3]}")
    return child_nodes

def get_capec_name(capec_id, capec_dir):
    capec_file = os.path.join(capec_dir, f"capec_{capec_id}.csv")
    if os.path.exists(capec_file):
        with open(capec_file, newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                return row['Name']
    return f"CAPEC-{capec_id}"

def build_attack_tree(name, id, execution_flow_data, child_nodes, capec_dir):
    tree = [f"{name} (CAPEC-{id})"]
    
    for obj_idx, (objective, methods) in enumerate(execution_flow_data):
        obj_prefix = '└─' if obj_idx == len(execution_flow_data) - 1 else '├─'
        tree.append(f"{obj_prefix} Attack Objective: {objective}")
        indent = '   ' if obj_prefix == '└─' else '│  '
        
        for method_idx, method in enumerate(methods):
            m_prefix = '└─' if method_idx == len(methods) - 1 else '├─'
            tree.append(f"{indent}{m_prefix} Attack Method: {method.actionableBody}")

    if child_nodes:
        tree.append(f"└─ Potential Child Nodes:")
        for k, child in enumerate(child_nodes):
            child_name = get_capec_name(child.split('-')[1], capec_dir)
            c_prefix = '├─' if k < len(child_nodes) - 1 else '└─'
            tree.append(f"   {c_prefix} {child_name} ({child})")

    return '\n'.join(tree)

def process_capec(capec_id, capec_dir):
    capec_file = os.path.join(capec_dir, f"capec_{capec_id}.csv")
    if not os.path.exists(capec_file):
        print(f"CAPEC-{capec_id} file not found.")
        return
    
    with open(capec_file, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            execution_flow_data = parse_execution_flow(row['Execution Flow'])
            child_nodes = parse_related_patterns(row['Related Attack Patterns'])
            attack_tree = build_attack_tree(row['Name'], row['ID'], execution_flow_data, child_nodes, capec_dir)
            print(attack_tree)

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

process_capec("234", "./capec_data/")