# autoAttackTreeGeneration
A script for automatic generation of an attack tree for a given CAPEC.

Requires a generative model (DeepSeek/OpenAI or similar) running on the specified endpoint in the code. Can run locally or use external API, but endpoint should be updated accordingly. 

ID of CAPEC to generate attack tree for is changed as an argument when calling process_capec (see bottom)
