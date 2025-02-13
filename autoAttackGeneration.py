import os
import csv
import requests
import json
import re
import ast

class Node:
    def __init__(self, originalBody="", actionableBody="", children=None):
        self.originalBody = originalBody
        self.actionableBody = actionableBody
        self.children = children if children is not None else []

def parse_execution_flow(execution_flow):
    instructionsSummarize = (
        "Rewrite the text as a super short, actionable step. "
        "You should NOT add anything, such as further instructions or additional information, to the text. "
        "It should only be text, no markdown, code, lists or anything like that."
    )
    
    instructionsChildren = (
        "Create zero to four methods or prerequisites for this method to be executed, as if they were child nodes to the given method in an attack tree. "
        "For example if the method is to get the combination from the target, the child nodes could be threaten, blackmail, eavesdrop or bribe. "
        "Format response as a JSON array of strings (not dictionaries) containing ONLY the short, actionable steps. "
        "Example: [\"Step 1\", \"Step 2\", \"Step 3\"]"
    )

    instructionsAdditionalMethods = (
        "Generate up to 2 additional attack methods for the following attack objective. "
        "They should be short, actionable steps and not duplicates of any methods already provided. "
        "Use the entire objective description provided below. "
        "Format the response as a JSON array of strings (not dictionaries) containing ONLY the short, "
        "actionable steps, no markdown, code, lists or anything like that. For example: [\"Method 1\", \"Method 2\"]"
    )
    
    steps = execution_flow.split('::STEP:')[1:]
    objectives = []
    
    for step in steps:
        if 'DESCRIPTION:[' in step:
            start = step.index('DESCRIPTION:[') + len('DESCRIPTION:[')
            end = step.index(']', start)
            objective_title = step[start:end].strip()
            # Attempt to extract the full objective description:
            tech_index = step.find(':TECHNIQUE:', end)
            if tech_index == -1:
                objective_full = step[end+1:].strip()
            else:
                objective_full = step[end+1:tech_index].strip()
            if not objective_full:
                objective_full = objective_title
            objective = f"[{objective_title}]"
        else:
            objective_title = ""
            objective_full = ""
            objective = None

        methods = []
        technique_parts = step.split('TECHNIQUE:')[1:]
        for tech in technique_parts:
            method = tech.split('::', 1)[0].strip()
            if method:
                actionable_method = callGPT(instructionsSummarize, method)
                children_str = callGPT(instructionsChildren, method)
                children_list = []
                
                json_match = re.search(r'(\[.*?\]|\{.*?\})', children_str, re.DOTALL)
                if json_match:
                    children_str = json_match.group(1)
                    try:
                        parsed = json.loads(children_str)
                        if isinstance(parsed, list):
                            children_list = parsed
                        elif isinstance(parsed, dict):
                            children_list = parsed.get('prerequisites', []) + parsed.get('children', [])
                    except json.JSONDecodeError:
                        try:
                            parsed = ast.literal_eval(children_str)
                            if isinstance(parsed, list):
                                children_list = parsed
                            elif isinstance(parsed, dict):
                                children_list = parsed.get('prerequisites', []) + parsed.get('children', [])
                        except:
                            children_list = []
                
                child_nodes = []
                for item in children_list[:3]:
                    original_body = str(item)
                    actionable_body = original_body  # Default value
                    
                    if isinstance(item, dict):
                        actionable_body = item.get('description', 
                            item.get('title',
                            item.get('prerequisite',
                            item.get('method',
                            item.get('step', original_body)))))
                    elif isinstance(item, str):
                        actionable_body = item.replace('"', '').replace("{", "").replace("}", "").strip()
                    
                    child_nodes.append(Node(
                        originalBody=original_body,
                        actionableBody=actionable_body
                    ))

                methods.append(Node(method, actionable_method, child_nodes))
        
        if objective_full:
            additional_methods_str = callGPT(instructionsAdditionalMethods, objective_full)
            try:
                additional_methods = json.loads(additional_methods_str)
                if not isinstance(additional_methods, list):
                    additional_methods = []
            except Exception as e:
                try:
                    additional_methods = ast.literal_eval(additional_methods_str)
                    if not isinstance(additional_methods, list):
                        additional_methods = []
                except:
                    additional_methods = []
            for add_method in additional_methods:
                actionable_method = callGPT(instructionsSummarize, add_method)
                children_str = callGPT(instructionsChildren, add_method)
                children_list = []
                json_match = re.search(r'(\[.*?\]|\{.*?\})', children_str, re.DOTALL)
                if json_match:
                    children_str = json_match.group(1)
                    try:
                        parsed = json.loads(children_str)
                        if isinstance(parsed, list):
                            children_list = parsed
                        elif isinstance(parsed, dict):
                            children_list = parsed.get('prerequisites', []) + parsed.get('children', [])
                    except json.JSONDecodeError:
                        try:
                            parsed = ast.literal_eval(children_str)
                            if isinstance(parsed, list):
                                children_list = parsed
                            elif isinstance(parsed, dict):
                                children_list = parsed.get('prerequisites', []) + parsed.get('children', [])
                        except:
                            children_list = []
                child_nodes = []
                for item in children_list[:3]:
                    original_body = str(item)
                    actionable_body = original_body
                    if isinstance(item, dict):
                        actionable_body = item.get('description', 
                            item.get('title',
                            item.get('prerequisite',
                            item.get('method',
                            item.get('step', original_body)))))
                    elif isinstance(item, str):
                        actionable_body = item.replace('"', '').replace("{", "").replace("}", "").strip()
                    child_nodes.append(Node(originalBody=original_body, actionableBody=actionable_body))
                methods.append(Node(add_method, actionable_method, child_nodes))
                
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
    total_objectives = len(execution_flow_data)
    has_child_nodes = bool(child_nodes)
    
    for obj_idx, (objective, methods) in enumerate(execution_flow_data):
        obj_prefix = '├─' if (obj_idx < total_objectives - 1) or has_child_nodes else '└─'
        tree.append(f"{obj_prefix} Attack Objective: {objective}")
        indent = '│  ' if obj_prefix == '├─' else '   '
        
        for method_idx, method in enumerate(methods):
            m_prefix = '├─' if method_idx < len(methods) - 1 else '└─'
            tree.append(f"{indent}{m_prefix} Attack Method: {method.actionableBody}")
            
            if method.children:
                child_indent = indent + ('│  ' if m_prefix == '├─' else '   ')
                for child_idx, child in enumerate(method.children):
                    c_prefix = '├─' if child_idx < len(method.children) - 1 else '└─'
                    tree.append(f"{child_indent}{c_prefix} {child.actionableBody}")

    if child_nodes:
        tree.append(f"└─ Potential Child Nodes:" if total_objectives > 0 else "Potential Child Nodes:")
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
