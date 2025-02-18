import csv
import time
import requests
from bs4 import BeautifulSoup

def get_related_attack_patterns(capec_id):
    """
    Fetches the CAPEC definition page for the given capec_id and extracts
    the Relationships table. Returns a string formatted as:
    
      ::NATURE:ChildOf:CAPEC ID:560::NATURE:CanPrecede:CAPEC ID:151::NATURE:CanPrecede:CAPEC ID:653::
      
    If no relationships are found, returns an empty string.
    """
    url = f"https://capec.mitre.org/data/definitions/{capec_id}.html"
    print(f"Fetching {url} ...")
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            print(f"[{capec_id}] HTTP error: {response.status_code}")
            return ""
        soup = BeautifulSoup(response.content, 'html.parser')
        
        relationships_div = soup.find("div", id="Relationships")
        if not relationships_div:
            print(f"[{capec_id}] No Relationships section found.")
            return ""
        
        tables = relationships_div.find_all("table")
        target_table = None
        for table in tables:
            header_row = table.find("tr")
            if header_row and "Nature" in header_row.get_text():
                target_table = table
                break
        
        if not target_table:
            print(f"[{capec_id}] No valid Relationships table found.")
            return ""
        
        rows = target_table.find_all("tr")
        relationships_str = ""
        for row in rows[1:]:
            cells = row.find_all("td")
            if len(cells) < 3:
                continue
            nature = cells[0].get_text(strip=True)
            rel_id = cells[2].get_text(strip=True)
            relationships_str += f"::NATURE:{nature}:CAPEC ID:{rel_id}"
        if relationships_str:
            relationships_str += "::"
            print(f"[{capec_id}] Extracted: {relationships_str}")
        else:
            print(f"[{capec_id}] No relationships extracted.")
        return relationships_str
    except Exception as e:
        print(f"[{capec_id}] Exception: {e}")
        return ""

def main():
    input_csv = "capec_data.csv"            # Update to CSV filename
    output_csv = "capec_updated.csv" 

    updated_rows = []
    with open(input_csv, newline='', encoding="utf-8") as infile:
        reader = csv.DictReader(infile)
        fieldnames = [f for f in reader.fieldnames if f is not None]
        if "Related Attack Patterns" not in fieldnames:
            fieldnames.append("Related Attack Patterns")
        
        for row in reader:
            if None in row:
                del row[None]
            capec_id = row.get("ID", "").strip()
            if not capec_id:
                print("Skipping a row with no CAPEC ID.")
                updated_rows.append(row)
                continue

            related_attack_patterns = get_related_attack_patterns(capec_id)
            row["Related Attack Patterns"] = related_attack_patterns
            updated_rows.append(row)
            time.sleep(1)
    
    with open(output_csv, "w", newline='', encoding="utf-8") as outfile:
        writer = csv.DictWriter(outfile, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(updated_rows)
    
    print(f"Updated CSV written to {output_csv}")

if __name__ == "__main__":
    main()
