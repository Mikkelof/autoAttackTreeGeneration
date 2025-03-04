# autoAttackTreeGeneration
A script for automatic generation of an attack tree for a given CAPEC.

Requires a generative model (DeepSeek/OpenAI or similar) running on the specified endpoint in the code. Can run locally or use external API, but endpoint should be updated accordingly. 

ID of CAPEC to generate attack tree for is changed by modifying starting_capec_id in the generate_attack_tree_graph function

update_CAPEC_data scrapes up-to-date from the CAPEC site and updated the csv file. Currently only updated the related attack patterns.

split_file splits the file from update_CAPEC_data into seperate files and adds them to the capec_data folder for use in the main script