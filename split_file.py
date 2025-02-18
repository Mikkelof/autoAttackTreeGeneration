import os
import csv

def split_capec_entries(input_file):
    output_dir = "./capec_data/"
    os.makedirs(output_dir, exist_ok=True)
    
    with open(input_file, newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        headers = next(reader)
        
        for row in reader:
            if not row:
                continue
            capec_id = row[0]
            output_file = os.path.join(output_dir, f"capec_{capec_id}.csv")
            
            with open(output_file, mode='w', newline='', encoding='utf-8') as outfile:
                writer = csv.writer(outfile)
                writer.writerow(headers)
                writer.writerow(row)
    
    print(f"Successfully split CAPEC entries into {output_dir}")

split_capec_entries("capec_updated.csv")
