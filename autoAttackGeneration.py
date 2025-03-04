import os
import csv
import requests
import json
import re
import html
from collections import defaultdict
from graphviz import Digraph

class Node:
    def __init__(self, originalBody="", actionableBody=""):
        self.originalBody = originalBody
        self.actionableBody = actionableBody

class GraphNode:
    def __init__(self, label, dimmed=False):
        self.label = label
        self.dimmed = dimmed
        self.children = []

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
    if capec_id.startswith("CAPEC-"):
        capec_id = capec_id.split('-')[1]
    capec_file = os.path.join(capec_dir, f"capec_{capec_id}.csv")
    if os.path.exists(capec_file):
        with open(capec_file, newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                abstraction = row['Abstraction']
                if abstraction in ('Standard', 'Detailed'):
                    return True
    return False

def parse_related_cwe_ids(related_cwe_text):
    return re.findall(r'::(\d+)::', related_cwe_text)

def generate_cwe_attack_steps_for_all(cwe_ids, cwe_dir, num_steps=3):
    all_cwe_info = ""
    for cwe_id in cwe_ids:
        cwe_file = os.path.join(cwe_dir, f"cwe_{cwe_id}.csv")
        if os.path.exists(cwe_file):
            with open(cwe_file, newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    cwe_info = (
                        f"Name: {row['Name']}. "
                        f"Description: {row['Description']}. "
                        f"Extended Description: {row['Extended Description']}."
                        f"Observed Examples: {row['Observed Examples']}."
                    )
                    all_cwe_info += cwe_info + "\n"
    if not all_cwe_info:
        return []
    
    instructions_cwe = (
        f"Generate {num_steps} concise attack steps following these rules:\n"
        "1. Each step MUST start with a strong imperative verb (for example, but not limited to 'Intercept', 'Bypass' or 'Brute-force')\n"
        "2. Never use markdown, asterisks (**), bold, italics, or special formatting\n"
        "3. Follow this exact format: '[action verb] [method] to [impact]'\n"
        "4. Never mention 'attackers can' - focus on direct actions\n"
        "5. Do NOT start with 'Step 1:' or '1.' or any numbering, skip directly to the verb'\n"
        "6. Use complete sentences but keep under 15 words\n\n"
        "Bad Example: **Step 1:** Intercept CAPTCHA mechanisms by...\n"
        "Good Example: Exploit weak password requirements to bypass authentication mechanisms\n\n"
        "Now generate plain text steps following these rules."
    )
        
    response = callGPT(instructions_cwe, all_cwe_info)
    steps = [step.strip() for step in response.split('\n') if step.strip()]
    return steps

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

def process_capec_graph(capec_id, capec_dir, cwe_dir, current_path=None, duplicates=None):
    if current_path is None:
        current_path = []
    if duplicates is None:
        duplicates = defaultdict(int)
    
    if capec_id.startswith("CAPEC-"):
        capec_id = capec_id.split('-')[1]
    
    if capec_id in current_path:
        return None
    
    duplicates[capec_id] += 1
    
    capec_file = os.path.join(capec_dir, f"capec_{capec_id}.csv")
    if not os.path.exists(capec_file):
        print(f"CAPEC-{capec_id} file not found.")
        return None
    
    with open(capec_file, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            execution_flow_data = parse_execution_flow(row['Execution Flow'])
            child_nodes = parse_related_patterns(row['Related Attack Patterns'], capec_dir)
            root_label = f"{row['Name']} (CAPEC-{capec_id})"
            if duplicates[capec_id] > 1:
                root_label += " (duplicate)"
            root_node = GraphNode(root_label)
            
            for objective, methods in execution_flow_data:
                objective_node = GraphNode(f"Attack Objective: {objective}")
                for method in methods:
                    objective_node.children.append(GraphNode(f"Attack Method: {method.actionableBody}"))
                root_node.children.append(objective_node)
            
            if child_nodes:
                for child in child_nodes:
                    child_id = child.split('-')[1]
                    child_graph = process_capec_graph(child_id, capec_dir, cwe_dir, current_path + [capec_id], duplicates)
                    if child_graph is not None:
                        root_node.children.append(child_graph)
            
            cwe_field = row.get('Related Weaknesses', '')
            cwe_ids = parse_related_cwe_ids(cwe_field)
            if cwe_ids:
                cwe_attack_steps = generate_cwe_attack_steps_for_all(cwe_ids, cwe_dir, num_steps=3)
                for step in cwe_attack_steps:
                    root_node.children.append(GraphNode(f"Generated Attack Method: {step}"))
            
            return root_node
    return None

def get_ancestry_chain(capec_id, capec_dir):
    chain = []
    current_id = capec_id.split('-')[1] if capec_id.startswith("CAPEC-") else capec_id
    while True:
        chain.append(current_id)
        capec_file = os.path.join(capec_dir, f"capec_{current_id}.csv")
        if not os.path.exists(capec_file):
            break
        parent_id = None
        with open(capec_file, newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            row = next(reader, None)
            if row:
                related_patterns = row.get('Related Attack Patterns', '')
                for entry in related_patterns.split('::'):
                    parts = entry.split(':')
                    if len(parts) >= 4 and parts[0] == "NATURE" and parts[1] == "ChildOf":
                        parent_id = parts[3].strip()
                        if parent_id.startswith("CAPEC-"):
                            parent_id = parent_id.split('-')[1]
                        break
        if parent_id:
            current_id = parent_id
        else:
            break
    chain.reverse()
    return chain

def get_capec_title(capec_id, capec_dir):
    capec_file = os.path.join(capec_dir, f"capec_{capec_id}.csv")
    if not os.path.exists(capec_file):
        return f"CAPEC-{capec_id}"
    with open(capec_file, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        row = next(reader, None)
        if row:
            return row.get('Name', f"CAPEC-{capec_id}")
        else:
            return f"CAPEC-{capec_id}"

def parse_parent_of_relationships_for_capec(capec_id, capec_dir):
    children = []
    capec_file = os.path.join(capec_dir, f"capec_{capec_id}.csv")
    if not os.path.exists(capec_file):
        return children
    with open(capec_file, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        row = next(reader, None)
        if row:
            related_patterns = row.get('Related Attack Patterns', '')
            for entry in related_patterns.split('::'):
                parts = entry.split(':')
                if len(parts) >= 4 and parts[0] == "NATURE" and parts[1] == "ParentOf":
                    child_id = parts[3].strip()
                    if child_id.startswith("CAPEC-"):
                        child_id = child_id.split('-')[1]
                    children.append(child_id)
    return children

def build_ancestry_subtree_graph(chain, index, capec_dir, elaborated_tree):
    current_id = chain[index]
    current_title = get_capec_title(current_id, capec_dir)
    node_label = f"{current_title} (CAPEC-{current_id})"
    tree_node = GraphNode(node_label)
    
    if index < len(chain) - 1:
        children_ids = parse_parent_of_relationships_for_capec(current_id, capec_dir)
        relevant_child = chain[index + 1]
        if relevant_child not in children_ids:
            children_ids.append(relevant_child)
        children_ids = list(dict.fromkeys(children_ids))
        
        for child_id in children_ids:
            child_title = get_capec_title(child_id, capec_dir)
            if child_id == relevant_child:
                subtree = build_ancestry_subtree_graph(chain, index + 1, capec_dir, elaborated_tree)
                tree_node.children.append(subtree)
            else:
                tree_node.children.append(GraphNode(f"{child_title} (CAPEC-{child_id})", dimmed=True))
        return tree_node
    else:
        return elaborated_tree

def get_node_attributes(graph_node):
    if graph_node.dimmed:
        return {"style": "filled", "fillcolor": "gray80", "fontcolor": "gray50"}
    
    label = graph_node.label
    if label.startswith("Attack Objective:"):
         return {"style": "filled", "fillcolor": "red"}
    elif label.startswith("Attack Method:"):
         return {"style": "filled", "fillcolor": "yellow"}
    elif label.startswith("Generated Attack Method:"):
         return {"style": "filled", "fillcolor": "orange"}
    else:
         return {"style": "filled", "fillcolor": "lightblue"}

def add_nodes_edges(dot, graph_node, node_mapping, parent_id=None, node_counter=[1]):
    current_id = f"node{node_counter[0]}"
    node_counter[0] += 1
    node_mapping[current_id] = graph_node.label

    attrs = get_node_attributes(graph_node)
    dot.node(current_id, current_id, **attrs)
    
    if parent_id:
        dot.edge(parent_id, current_id)
    
    for child in graph_node.children:
        add_nodes_edges(dot, child, node_mapping, parent_id=current_id, node_counter=node_counter)

def generate_attack_tree_graph():
    starting_capec_id = "CAPEC-600"
    capec_dir = "./capec_data/"
    cwe_dir = "./cwe_data/"
    duplicates = defaultdict(int)
    
    elaborated_tree = process_capec_graph(starting_capec_id, capec_dir, cwe_dir, duplicates=duplicates)
    if elaborated_tree is None:
        print("No attack tree generated.")
        return
    
    ancestry_chain = get_ancestry_chain(starting_capec_id, capec_dir)
    if len(ancestry_chain) > 1:
        full_tree = build_ancestry_subtree_graph(ancestry_chain, 0, capec_dir, elaborated_tree)
    else:
        full_tree = elaborated_tree
    
    dot = Digraph(comment="CAPEC Attack Tree")
    node_mapping = {}
    add_nodes_edges(dot, full_tree, node_mapping)
    
    with dot.subgraph(name='cluster_legend') as c:
        c.attr(label='Node Types', style='dashed')
        legend_html = '<<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="4">'
        legend_html += '<TR><TD COLSPAN="2"><B>Color Codes</B></TD></TR>'
        legend_html += '<TR><TD bgcolor="lightblue"> </TD><TD><b>Main Nodes:</b> Nodes representing a specific CAPEC entry with title and ID</TD></TR>'
        legend_html += '<TR><TD bgcolor="red"> </TD><TD><b>Attack Objective Nodes:</b> Nodes representing the attack objectives taken directly from the parent CAPEC entry</TD></TR>'
        legend_html += '<TR><TD bgcolor="yellow"> </TD><TD><b>Attack Method Nodes:</b> Nodes representing the attack methods taken directly from the parent CAPEC entry</TD></TR>'
        legend_html += '<TR><TD bgcolor="orange"> </TD><TD><b>Generated Attack Method Nodes:</b> Nodes representing attack methods generated by a large language model (LLM) using data derived from the corresponding CWE entries linked to the parent CAPEC entry</TD></TR>'
        legend_html += '<TR><TD bgcolor="gray80"> </TD><TD><b>Other Children Nodes:</b> Nodes representing childen that are not relevant to the original CAPEC entry and are not expended on</TD></TR>'
        legend_html += '</TABLE>>'
        c.node('legend', legend_html, shape='none')
    
    mapping_html = '<<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="4">'
    mapping_html += '<TR><TD COLSPAN="2"><B>Node Mapping</B></TD></TR>'
    for key in sorted(node_mapping.keys(), key=lambda x: int(x.replace("node", ""))):
        mapping_text = html.escape(node_mapping[key])
        mapping_html += f'<TR><TD>{key}</TD><TD>{mapping_text}</TD></TR>'
    mapping_html += '</TABLE>>'
    
    with dot.subgraph(name='cluster_mapping') as c2:
        c2.attr(rank='sink', label='Node Mappings', style='dashed')
        c2.node('mapping', mapping_html, shape='none')
    
    with dot.subgraph(name='sink_cluster') as s:
        s.attr(rank='sink')
        s.node('dummy_sink', '', style='invis')
        s.edge('dummy_sink', 'mapping', style='invis')
    
    output_filename = 'attack_tree_graph'
    dot.render(output_filename, format='pdf', cleanup=True)
    print(f"Graph rendered to {output_filename}.pdf")
    
    print("\nDuplicate Nodes Report:")
    for cid, count in duplicates.items():
        if count > 1:
            print(f"- CAPEC-{cid} appears {count} times in the tree")

if __name__ == "__main__":
    generate_attack_tree_graph()
