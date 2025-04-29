# autoAttackTreeGeneration
A script for automatic generation of an attack-defense tree for a given CAPEC.

Requires a generative model (DeepSeek/OpenAI or similar) running on the specified endpoint in the code. Can run locally or use external API, but endpoint should be updated accordingly. 

Techincal language and syntactic complexity/complexities can be modified by changing adding or removing them from the relevant array when calling the main function at the bottom (see commented out function calls).

ID of CAPEC(s) to generate attack-defense tree(s) for is changed by modifying the capec_ids array with the ID(s) you want to generate trees for when calling the main function at the bottom.

update_CAPEC_data scrapes up-to-date from the CAPEC site and updated the csv file. Currently only updated the related attack patterns.

split_file splits the file from update_CAPEC_data into seperate files and adds them to the capec_data folder for use in the main script.