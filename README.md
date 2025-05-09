# eviseek

# References
# Learn what TextContext data types are (very annoying): https://gofastmcp.com/clients/client 

# TODO:

[✔️] a-1) get file alerts using the underlaying MCP protocol tool calling w/ out llm
[] a-2) cache "artifacts" (alert json blob) into a temp buffer (something that can hold the data and be used for referenceing)
[] a-3) download (pcap, bin) files from the json blob by indexing the blob list
[] a-4) create "evidence" entry in a temp database?? that or just cache the work
[] a-5) (pool threads for tasks, report a back log if needed) spawn a thread to wait for the run re_tools tool calls
[] a-5-1) send heartbeat to assemblyline4, ghidra, and objdump runners
[] a-5-2) build a json re:{} blob to give to the user
[] a-6) once the thread closes and write the work to the database based on an ID... then free the thread and keep workings

[] b-1) have a thread runner to push updates a document database... 
[] b-2) define some software that is able to call the database as a client for analyist analysis

[] c-1) create a SLM summarizer 

end goal: perhaps have an LLM generate a TIP (threat intel package)... save the person time



## evidence: 
"casefile": {
  "raw_alert": { ... },     // full original alert hit
  "analysis": [],           // post-processing modules can append reports here
  "artifacts": [],          // PCAPs, binaries, filenames, etc.
  "tags": [],               // analyst- or tool-applied tags
  "notes": ""               // comment or summary
}

# TODO:
#Read thishttps://cybercentrecanada.github.io/assemblyline4_docs/integration/python/
# 1) make the a 10 second checker to check if there were any new securityonion elasticsearch updates (make credentials the top most variables for now)
# 2) if so update the local database
# 3) for every (post adding it to databas in the custom format) call a function called processbinary
# 4) take the none pcap from the artifcats and download it to the tmp dir
# 5) send the file to assemblylinev4 for processing
# 6) wait for assemblyline to return output and print the output response


# ________________ NOTES ________________
# Full SubmissionParams with defaults based on documentation
    # params = {
    #     "classification": classification,
    #     "description": description,
    #     "name": filename,
    #     "deep_scan": True,
    #     "ignore_cache": True,
    #     "ignore_filtering": True,
    #     "ignore_recursion_prevention": True,
    #     "ignore_size": True,
    #     "ignore_dynamic_recursion_prevention": False,
    #     "submitter": self.user,
    #     "priority": 1000,
    #     "ttl": 30,
    #     "max_extracted": 500,
    #     "max_supplementary": 500,
    #     "services": {
    #         "selected": [],
    #         "excluded": [],
    #         "resubmit": []
    #     },
    #     "service_spec": {
    #         "Extract": {
    #             "password": "infected"
    #         }
    #     },
    #     "tags": [],
    #     "metadata": metadata,
    #     "params": {},
    #     "stream_sha256": None,
    #     "type": "file",
    #     "default_delay": 0,
    #     "disable_dynamic_recursion_prevention": False,
    #     "generate_alert": True,
    #     "filtering_heuristic_override": [],
    #     "group": None,
    #     "submission_id": None
    # }

#Param details: https://cybercentrecanada.github.io/assemblyline4_docs/odm/models/submission/#submissionparams
#Params: https://cybercentrecanada.github.io/assemblyline4_docs/integration/python/#__tabbed_1_2



