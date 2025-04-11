import os
import csv
import requests
import json
import re
import html
from collections import defaultdict
from graphviz import Digraph
import math

class Node:
    def __init__(self, originalBody="", actionableBody=""):
        self.originalBody = originalBody
        self.actionableBody = actionableBody

class GraphNode:
    def __init__(self, label, dimmed=False, is_and=False):
        self.label = label
        self.dimmed = dimmed
        self.children = []
        self.is_and = is_and

    def word_count(self):
        if "(CAPEC-" in self.label:
            return 0
        prefixes = ["Attack Objective: ", "Attack Method: ", "Generated Attack Method: ", "Mitigation: ", "Generated Countermeasure: "]
        for prefix in prefixes:
            if self.label.startswith(prefix):
                text = self.label[len(prefix):].strip()
                words = text.split()
                return len(words)
        return 0

def count_nodes_excluding_and(node):
    if node.is_and:
        count = 0
    else:
        count = 1
    for child in node.children:
        count += count_nodes_excluding_and(child)
    return count

def load_glossary(glossary_file):
    with open(glossary_file, 'r', encoding='utf-8-sig') as f:
        data = json.load(f)
    terms = [entry['term'].lower() for entry in data['parentTerms']]
    return terms

def count_matches(text, glossary_terms):
    text_lower = text.lower()
    words = text_lower.split()
    matched_positions = set()
    for term in glossary_terms:
        term_words = term.split()
        term_length = len(term_words)
        for i in range(len(words) - term_length + 1):
            if words[i:i + term_length] == term_words:
                for j in range(i, i + term_length):
                    matched_positions.add(j)
    return len(matched_positions)

def total_word_and_match_count(node, glossary_terms):
    if node.is_and:
        word_count = 0
        match_count = 0
    else:
        prefixes = ["Attack Objective: ", "Attack Method: ", "Generated Attack Method: ", "Mitigation: ", "Generated Countermeasure: "]
        for prefix in prefixes:
            if node.label.startswith(prefix):
                text = node.label[len(prefix):].strip()
                words = text.split()
                word_count = len(words)
                match_count = count_matches(text, glossary_terms)
                break
        else:
            word_count = 0
            match_count = 0
    for child in node.children:
        child_word_count, child_match_count = total_word_and_match_count(child, glossary_terms)
        word_count += child_word_count
        match_count += child_match_count
    return word_count, match_count

def adjust_language_complexity(text, complexity):
    if complexity == 'non-technical':
        instructions = (
            "You MUST respond with only one sentence. Provide NO additional text or explanation whatsoever.\n"
            "Rewrite the following text as one extremely simple, short sentence starting with an action verb (like 'Use', 'Find', 'Stop').\n"
            "Use only common, everyday words suitable for someone with ZERO technical knowledge. \n"
            "AVOID ALL technical terms, cybersecurity jargon, acronyms, or complex concepts. Focus on the basic action or prevention."
        )
    elif complexity == 'developer':
        instructions = (
            "You MUST respond with only one sentence. Provide NO additional text or explanation whatsoever.\n"
            "Rewrite the following text as one concise sentence starting with an action verb (like 'Implement', 'Validate', 'Query', 'Configure').\n"
            "Use clear technical terms appropriate for software developers, focusing on code, APIs, data handling, configuration, or common libraries/frameworks. Maintain technical accuracy but keep it brief."
        )
    elif complexity == 'expert':
        instructions = (
            "You MUST respond with only one sentence. Provide NO additional text or explanation whatsoever.\n"
            "Rewrite the following text as one concise sentence starting with a strong action verb (like 'Exploit', 'Inject', 'Enforce', 'Harden').\n"
            "Use precise, specific cybersecurity terminology (e.g., mention specific vulnerability classes like 'SQL Injection', 'Cross-Site Scripting', protocols, or advanced techniques) suitable for security professionals. Prioritize technical accuracy and specificity."
        )
    else:
        return text
    
    return callGPT(instructions, text, complexity)

def parse_execution_flow(execution_flow, language_complexity):
    steps = execution_flow.split('::STEP:')[1:]
    objectives = []
    
    for step_idx, step in enumerate(steps, 1):
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
        else:
            objective = f"[Step {step_idx}]"
        
        methods = []
        technique_parts = step.split('TECHNIQUE:')[1:]
        for tech in technique_parts:
            method = tech.split('::', 1)[0].strip()
            if method:
                actionable_method = adjust_language_complexity(method, language_complexity)
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

def generate_cwe_attack_steps_for_all(cwe_ids, cwe_dir, language_complexity, num_steps=3):
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
    
    base_prompt = (
        f"Generate {num_steps} concise attack steps following these rules:\n"
        "1. Each step MUST start with a strong imperative verb (for example, but not limited to 'Intercept', 'Bypass' or 'Brute-force')\n"
        "2. Never use markdown, asterisks (**), bold, italics, or special formatting\n"
        "3. Follow this exact format: '[action verb] [method] to [impact]'\n"
        "4. Never mention 'attackers can' - focus on direct actions\n"
        "5. Do NOT start with 'Step 1:' or '1.' or any numbering, skip directly to the verb\n"
        "6. Use complete sentences but keep under 15 words\n\n"
        "Bad Example: **Step 1:** Intercept CAPTCHA mechanisms by...\n"
        "Good Example: Exploit weak password requirements to bypass authentication mechanisms\n"
    )
    
    if language_complexity == 'non-technical':
        language_instruction = (
            "Use EXTREMELY simple, everyday language. AVOID ALL technical terms, jargon, or acronyms. "
            "Focus only on the core action in plain English understandable by a complete novice."
        )
    elif language_complexity == 'developer':
        language_instruction = (
            "Use technical terms relevant to software developers (e.g., input validation, API calls, database interactions, session management, configuration errors). "
            "Focus on actions related to code, data, or system configuration."
        )
    elif language_complexity == 'expert':
        language_instruction = (
            "Use precise and specific cybersecurity terminology. Mention specific attack types (e.g., SQLi, XSS, RCE), "
            "advanced techniques, or protocol manipulation where applicable. Assume deep technical knowledge."
        )
    else:
        language_instruction = ""
    
    instructions_cwe = base_prompt + language_instruction + "\nNow generate plain text steps following these rules."
    
    response = callGPT(instructions_cwe, all_cwe_info, language_complexity)
    steps = [step.strip() for step in response.split('\n') if step.strip()]
    return steps

def parse_mitigations(mitigations_text):
    return [m.strip() for m in mitigations_text.split("::") if m.strip()]

def get_cwe_potential_mitigations(cwe_id, cwe_dir):
    potential_mitigations = []
    cwe_file = os.path.join(cwe_dir, f"cwe_{cwe_id}.csv")
    if os.path.exists(cwe_file):
        with open(cwe_file, newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                pm = row.get('Potential Mitigations', '')
                if pm:
                    potential_mitigations.extend([p.strip() for p in pm.split("::") if p.strip()])
    return potential_mitigations

def get_combined_cwe_potential_mitigations(cwe_ids, cwe_dir):
    combined = []
    for cwe_id in cwe_ids:
        combined.extend(get_cwe_potential_mitigations(cwe_id, cwe_dir))
    return combined

def generate_countermeasures_for_attack_method(attack_method_text, mitigation_context, language_complexity):
    base_prompt = (
        "Generate ONE concise countermeasure using the following input while following these rules:\n"
        "1. The countermeasure must start with a strong imperative verb (e.g., 'Implement', 'Deploy', 'Enforce')\n"
        "2. Never use markdown, asterisks (**), bold, italics, or special formatting\n"
        "3. Follow this exact format: '[action verb] [defense method] to [prevent impact]'\n"
        "4. Do not include any implementation instructions, reasoning, drafts or additional information, just the countermeasure as a single sentence\n"
    )
    
    if language_complexity == 'non-technical':
        language_instruction = (
            "Use EXTREMELY simple, everyday language. AVOID ALL technical terms, jargon, or acronyms. "
            "Focus on the basic preventative action in plain English understandable by anyone."
        )
    elif language_complexity == 'developer':
        language_instruction = (
            "Use technical terms relevant to software developers (e.g., input sanitization, output encoding, parameterization, secure coding practices, API rate limiting, proper configuration). "
            "Focus on practical implementation steps."
        )
    elif language_complexity == 'expert':
        language_instruction = (
            "Use precise and specific cybersecurity terminology. Mention specific security controls (e.g., WAF rules, CSP directives, HSTS), "
            "architectural patterns, cryptographic techniques, or advanced configurations. Assume deep technical knowledge."
        )
    else:
        language_instruction = ""
    
    instructions_countermeasure = base_prompt + language_instruction + "\nNow generate ONLY the plain text countermeasure as a single sentence. Do NOT generate multiple countermeasures or anything beyond that single sentence."
    
    combined_input = f"Attack Method: {attack_method_text}\nMitigation Context: {mitigation_context}"
    response = callGPT(instructions_countermeasure, combined_input, language_complexity)
    steps = [step.strip() for step in response.split('\n') if step.strip()]
    return steps

def callGPT(instructions, originalText, complexity_level):
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

def process_capec_graph(capec_id, capec_dir, cwe_dir, current_path=None, duplicates=None, language_complexity='developer', syntax_complexity='full'):
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
            execution_flow_data = parse_execution_flow(row['Execution Flow'], language_complexity)
            objectives = [(objective, methods) for objective, methods in execution_flow_data]
            
            mitigations_list = parse_mitigations(row.get('Mitigations', ''))
            adjusted_mitigations = [adjust_language_complexity(m, language_complexity) for m in mitigations_list]
            
            cwe_ids = parse_related_cwe_ids(row.get('Related Weaknesses', ''))
            combined_cwe_potential = get_combined_cwe_potential_mitigations(cwe_ids, cwe_dir)
            context = "CAPEC mitigations: " + " ".join(adjusted_mitigations)
            if combined_cwe_potential:
                context += " CWE potential mitigations: " + " ".join(combined_cwe_potential)
            
            root_label = f"{row['Name']} (CAPEC-{capec_id})"
            if duplicates[capec_id] > 1:
                root_label += " (duplicate)"
            root_node = GraphNode(root_label)
            
            for mitigation in adjusted_mitigations:
                root_node.children.append(GraphNode(f"Mitigation: {mitigation}"))
            
            if len(objectives) > 1:
                and_node = GraphNode("AND", is_and=True)
                for objective, methods in objectives:
                    objective_text = adjust_language_complexity(objective, language_complexity)
                    objective_node = GraphNode(f"Attack Objective: {objective_text}")
                    for method in methods:
                        attack_label = f"Attack Method: {method.actionableBody}"
                        attack_method_node = GraphNode(attack_label)
                        if syntax_complexity in ['countermeasures', 'full']:
                            generated_countermeasures = generate_countermeasures_for_attack_method(
                                method.originalBody, context, language_complexity
                            )
                            for cm in generated_countermeasures:
                                attack_method_node.children.append(GraphNode(f"Generated Countermeasure: {cm}"))
                        objective_node.children.append(attack_method_node)
                    and_node.children.append(objective_node)
                root_node.children.append(and_node)
            elif objectives:
                objective, methods = objectives[0]
                objective_text = adjust_language_complexity(objective, language_complexity)
                objective_node = GraphNode(f"Attack Objective: {objective_text}")
                for method in methods:
                    attack_label = f"Attack Method: {method.actionableBody}"
                    attack_method_node = GraphNode(attack_label)
                    if syntax_complexity in ['countermeasures', 'full']:
                        generated_countermeasures = generate_countermeasures_for_attack_method(
                            method.originalBody, context, language_complexity
                        )
                        for cm in generated_countermeasures:
                            attack_method_node.children.append(GraphNode(f"Generated Countermeasure: {cm}"))
                    objective_node.children.append(attack_method_node)
                root_node.children.append(objective_node)
            
            child_nodes = parse_related_patterns(row['Related Attack Patterns'], capec_dir)
            if child_nodes:
                for child in child_nodes:
                    child_id = child.split('-')[1]
                    child_graph = process_capec_graph(child_id, capec_dir, cwe_dir, 
                                                     current_path + [capec_id], duplicates,
                                                     language_complexity, syntax_complexity)
                    if child_graph is not None:
                        root_node.children.append(child_graph)
            
            if syntax_complexity == 'full' and cwe_ids:
                cwe_attack_steps = generate_cwe_attack_steps_for_all(cwe_ids, cwe_dir, language_complexity)
                for step in cwe_attack_steps:
                    attack_method_node = GraphNode(f"Generated Attack Method: {step}")
                    if syntax_complexity == 'full':
                        generated_countermeasures = generate_countermeasures_for_attack_method(
                            step, context, language_complexity
                        )
                        for cm in generated_countermeasures:
                            attack_method_node.children.append(GraphNode(f"Generated Countermeasure: {cm}"))
                    root_node.children.append(attack_method_node)
            
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
    if graph_node.is_and:
        return {"style": "filled", "fillcolor": "white", "fontcolor": "black", "shape": "triangle"}
    
    if graph_node.dimmed:
        return {"style": "filled", "fillcolor": "gray80", "fontcolor": "gray50"}
    
    label = graph_node.label
    if label.startswith("Attack Objective:"):
         return {"style": "filled", "fillcolor": "red"}
    elif label.startswith("Attack Method:"):
         return {"style": "filled", "fillcolor": "yellow"}
    elif label.startswith("Generated Attack Method:"):
         return {"style": "filled", "fillcolor": "orange"}
    elif label.startswith("Mitigation:"):
         return {"style": "filled", "fillcolor": "lightgreen", "shape": "rectangle"}
    elif label.startswith("Generated Countermeasure:"):
         return {"style": "filled", "fillcolor": "forestgreen", "shape": "rectangle"}
    else:
         return {"style": "filled", "fillcolor": "lightblue"}

def add_nodes_edges(dot, graph_node, node_mapping, parent_id=None, parent_label=None, mapping_counter=[1], and_counter=[1]):
    if graph_node.is_and:
        current_id = "and" + str(and_counter[0])
        and_counter[0] += 1
        node_label = "AND"
    else:
        current_id = "node" + str(mapping_counter[0])
        mapping_counter[0] += 1
        node_label = current_id
        node_mapping[current_id] = graph_node.label

    dot.node(current_id, node_label, **get_node_attributes(graph_node))
    if parent_id:
        edge_style = {}
        if graph_node.label.startswith("Mitigation:") or graph_node.label.startswith("Generated Countermeasure:"):
            edge_style["style"] = "dotted"
        dot.edge(parent_id, current_id, **edge_style)
    
    for child in graph_node.children:
        add_nodes_edges(dot, child, node_mapping, parent_id=current_id, parent_label=graph_node.label, mapping_counter=mapping_counter, and_counter=and_counter)

def generate_attack_tree_graph(capec_id, language_complexity='developer', syntax_complexity='full'):
    starting_capec_id = f"CAPEC-{capec_id}"
    capec_dir = "./capec_data/"
    cwe_dir = "./cwe_data/"
    glossary_file = "nist_glossary.json"
    duplicates = defaultdict(int)
    
    glossary_terms = load_glossary(glossary_file)
    
    elaborated_tree = process_capec_graph(starting_capec_id, capec_dir, cwe_dir, 
                                        duplicates=duplicates, 
                                        language_complexity=language_complexity,
                                        syntax_complexity=syntax_complexity)
    if elaborated_tree is None:
        print("No attack-defense tree generated.")
        return
    
    ancestry_chain = get_ancestry_chain(starting_capec_id, capec_dir)
    if len(ancestry_chain) > 1:
        full_tree = build_ancestry_subtree_graph(ancestry_chain, 0, capec_dir, elaborated_tree)
    else:
        full_tree = elaborated_tree
    
    total_nodes = count_nodes_excluding_and(full_tree)
    syntax_complexity_number = 1 - math.exp(-0.02 * total_nodes)
    
    total_words, total_matches = total_word_and_match_count(full_tree, glossary_terms)
    language_complexity_score = total_matches / total_words if total_words > 0 else 0
    
    print(f"\nStatistics:")
    print(f"Total number of words in the nodes: {total_words}")
    print(f"Total number of matches with glossary terms: {total_matches}")
    print(f"Language complexity: {language_complexity_score:.4f}")
    print(f"Total number of nodes (excluding AND-nodes): {total_nodes}")
    print(f"Syntax complexity: {syntax_complexity_number:.4f}")
    print(f"Total complexity: {(language_complexity_score*syntax_complexity_number):.4f}")

    
    dot = Digraph(comment="CAPEC Attack-Defense Tree")
    node_mapping = {}
    add_nodes_edges(dot, full_tree, node_mapping)
    
    with dot.subgraph(name='cluster_legend') as c:
        c.attr(label='Node Types', style='dashed')
        legend_html = '<<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="4">'
        legend_html += '<TR><TD COLSPAN="2"><B>Color Codes</B></TD></TR>'
        legend_html += '<TR><TD bgcolor="lightblue"> </TD><TD><b>Main Nodes:</b> CAPEC entries with title and ID</TD></TR>'
        legend_html += '<TR><TD bgcolor="red"> </TD><TD><b>Attack Objective Nodes:</b> Derived from CAPEC execution flow</TD></TR>'
        legend_html += '<TR><TD bgcolor="yellow"> </TD><TD><b>Attack Method Nodes:</b> Derived from execution flow</TD></TR>'
        legend_html += '<TR><TD bgcolor="orange"> </TD><TD><b>Generated Attack Method Nodes:</b> LLM-generated attack methods</TD></TR>'
        legend_html += '<TR><TD bgcolor="lightgreen"> </TD><TD><b>Mitigation Nodes:</b> Derived from the CAPEC mitigations</TD></TR>'
        legend_html += '<TR><TD bgcolor="forestgreen"> </TD><TD><b>Generated Countermeasure Nodes:</b> LLM-generated countermeasures</TD></TR>'
        legend_html += '<TR><TD bgcolor="gray80"> </TD><TD><b>Other Children Nodes:</b> Nodes representing non-expanded children</TD></TR>'
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
    
    output_filename = f'attack_defense_tree_{language_complexity}_{syntax_complexity}'
    dot.render(output_filename, format='pdf', cleanup=True)
    print(f"Graph rendered to {output_filename}.pdf")
    
    print("\nDuplicate Nodes Report:")
    for cid, count in duplicates.items():
        if count > 1:
            print(f"- CAPEC-{cid} appears {count} times in the tree")

if __name__ == "__main__":
    # Options: language_complexity = [non-technical, developer, expert], syntax_complexity = [basic, countermeasures, full]
    generate_attack_tree_graph(capec_id=588, language_complexity='non-technical', syntax_complexity='basic')
    generate_attack_tree_graph(capec_id=588, language_complexity='developer', syntax_complexity='basic')
    generate_attack_tree_graph(capec_id=588, language_complexity='expert', syntax_complexity='basic')
    generate_attack_tree_graph(capec_id=588, language_complexity='non-technical', syntax_complexity='countermeasures')
    generate_attack_tree_graph(capec_id=588, language_complexity='developer', syntax_complexity='countermeasures')
    generate_attack_tree_graph(capec_id=588, language_complexity='expert', syntax_complexity='countermeasures')
    generate_attack_tree_graph(capec_id=588, language_complexity='non-technical', syntax_complexity='full')
    generate_attack_tree_graph(capec_id=588, language_complexity='developer', syntax_complexity='full')
    generate_attack_tree_graph(capec_id=588, language_complexity='expert', syntax_complexity='full')