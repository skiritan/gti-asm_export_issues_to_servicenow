import os
import requests
import json
import pandas as pd
import asm_util as asm

# ------------------------------------------------------------
# Filed Mapping: SNOW field - ASM field 
# 1.
field_map_VulnerableItemDetection ={
    "Confirmed"                   : "confidence", 
    "Source status"               : "summary/status_new", 
    "Vulnerable Item/external_id" : "id",  # need to remap. 
    "Proof"                       : "details/proof",  
    "Solution/source_id"          : "name", # issue-name
    "Vulnerability"               : "identifiers/name",
    "Vulnerability"               : "details/name", 
    "Status"                      : "summary/status", 
    "First found"                 : "first_seen", 
    "Solution summary"            : "details/remediation",
    "Last found"                  : "last_seen",

    # for reference
    "_project_id"      : "project_id",        # reference  
    "_project_name"    : "project_name",      # reference  
    "_collection_name" : "collection",        # reference
    "_entity_uid"      : "entity_uid",        # reference
    "_entity_name"     : "entity_name",       # reference
    "_entity_type"     : "entity_type",       # reference
    "_pretty_name"     : "pretty_name",       #reference
    "_issue_uid"       : "uid",               #reference - issue_id
    "_cve"             : "identifiers/name",  # reference        
}

# 2. 
field_map_MandiantASMProjectsAndCollectionsConfiguration = {
    "Display Name"    : "display_name",
    "Project Name"    : "project_name",
    "Collection ID"   : "collection_id",
    "Collection Name" : "collection_name",
    "project_id"      : "Project ID", 
}

# 3.
field_map_NationalVulnerabilityDatabaseEntry  = {
    "Solution"            : "details/remediation", 
    "Classification"      : "details/category", 
    "ID"                  : "identifiers/name", 
    "Name"                : "details/pretty_name", 
    "Source Severity"     : "details/severity", 
    "Threat"              : "details/description",
    "Normalized Severity" : "details/severity",
    "Date Published"      : "details/added", 
    "Summary"             : "details/pretty_name",     
    "Summary"             : "details/description",  
       
    # for reference
    "_cve"                : "identifiers/name",   # reference                            
}

# 4. 
field_map_ThirdPartyVulnerabilityEntry = {
    "Vendor"              : "details/vendor", 
    "Date Published"      : "details/added",
    "Summary"             : "details/pretty_name",
    "Summary"             : "details/description", 
    "Preferred Solution"  : "name", 
    "ID"                  : "details/name", 
    "Source Severity"     : "details/severity",
    "Solution"            : "details/remediation",
    "Normalized Severity" : "details/severity", 
    "Category"            : "details/category", 
    "Threat"              : "details/description", 
    "Classification"      : "category", 
    "Name"                : "details/description",  
    
    # for reference
    "_vendor": "_vendor"  #reference
}


# 5. 
field_map_VulnerabilitySolution = {
    "Description" : "details/remediation",
    "Source ID"   : "name",
}

# 6. 
field_map_VulnerableItem = {
    "Description":"description",   
    "External ID" : "id",   # need to remap. 
    "Status" : "status",  
    "Short Description" : "summary/pretty_name",  
    "Vulnerability" : "identifiers/name", 
    "Vulnerability" : "details/name", 
    "State" : "summary/status", 

     # for reference
    "_project_id"      : "project_id",        # reference  
    "_project_name"    : "project_name",      # reference  
    "_collection_name" : "collection",        # reference
    "_entity_uid"      : "entity_uid",        # reference
    "_entity_name"     : "entity_name",       # reference
    "_entity_type"     : "entity_type",       # reference
    "_pretty_name"     : "pretty_name",       # reference
    "_issue_uid"       : "uid",               # reference - issue_id
    "_cve"             : "identifiers/name",  # reference    

}
# ------------------------------------------------------------
# 1.
def create_csv_for_VulnerableItemDetection( detail_issues :pd.DataFrame) -> bool:
    print(f"#1. create_csv_for_VulnerableItemDetection")

    # convert to ServiceNow field
    detail_issues["id"] = detail_issues["entity_name"]
    
    # extract servicenow field 
    out = pd.DataFrame()
    for snow_key,asm_key in field_map_VulnerableItemDetection.items() :
        if asm_key in detail_issues.keys():
            out[snow_key] = detail_issues[asm_key]
        else:
            print(f"\t{snow_key}  {asm_key} - NG")
    # save 
    out.to_csv("./1_VulnerableItemDetection.csv",index=False)    
    return True

# ------------------------------------------------------------
# 2.
def create_csv_for_MandiantASMProjectsAndCollectionsConfiguration( collections_df :pd.DataFrame) -> bool:
    print(f"#2. create_csv_for_MandiantASMProjectsAndCollectionsConfiguration")
    # convert field mapping
    collections_df["display_name"]  = collections_df["printable_name"]
    collections_df["collection_id"]  = collections_df["id"]
    collections_df["collection_name"]  = collections_df["name"]
    collections_df["Project ID"]  = collections_df["project_id"]
    collections_df["_collection_printablename"]  = collections_df["printable_name"]

    # extract servicenow field 
    out = pd.DataFrame()
    for snow_key,asm_key in field_map_MandiantASMProjectsAndCollectionsConfiguration.items() :
        if asm_key in collections_df.keys():
            out[snow_key] = collections_df[asm_key]
        else:
            print(f"\t{snow_key}  {asm_key} - NG")

    # save
    out.to_csv("./2_MandiantASMProjectsAndCollectionsConfiguration.csv", index = False)    
    return True

# ------------------------------------------------------------
# 3.
def create_csv_for_NationalVulnerabilityDatabaseEntry(detail_issues :pd.DataFrame) -> bool:
    print(f"#3. create_csv_for_NationalVulnerabilityDatabaseEntry")
    # extract servicenow field 
    out = pd.DataFrame()
    for snow_key,asm_key in field_map_NationalVulnerabilityDatabaseEntry.items() :
        if asm_key in detail_issues.keys():
            out[snow_key] = detail_issues[asm_key]
        else:
            print(f"\t{snow_key}  {asm_key} - NG")
    out = out.drop_duplicates(["ID","Solution"])    

    # save
    out.to_csv("./3_NationalVulnerabilityDatabaseEntry.csv", index = False)    
    return True

# ------------------------------------------------------------
# 4.
def create_csv_for_ThirdPartyVulnerabilityEntry(detail_issues :pd.DataFrame) -> bool:
    print(f"#4. create_csv_for_ThirdPartyVulnerabilityEntry")
    # extract servicenow field 
    out = pd.DataFrame()
    for snow_key,asm_key in field_map_ThirdPartyVulnerabilityEntry.items() :
        if asm_key in detail_issues.keys():
            out[snow_key] = detail_issues[asm_key]
        else:
            print(f"\t{snow_key}  {asm_key} - NG")
    out = out.drop_duplicates("ID")    

    # save
    out.to_csv("./4_ThirdPartyVulnerabilityEntry.csv", index = False)    
    return True

# ------------------------------------------------------------
# 5.
def create_csv_for_VulnerabilitySolution(detail_issues :pd.DataFrame) -> bool:
    print(f"#5. create_csv_for_VulnerabilitySolution")
    # extract servicenow field 
    out = pd.DataFrame()
    for snow_key,asm_key in field_map_VulnerabilitySolution.items() :
        if asm_key in detail_issues.keys():
            out[snow_key] = detail_issues[asm_key]
        else:
            print(f"\t{snow_key}  {asm_key} - NG")
    out = out.drop_duplicates("Source ID")    

    # save
    out.to_csv("./5_VulnerabilitySolution.csv", index = False)    
    return True

# ------------------------------------------------------------
# 6.
def create_csv_for_field_map_VulnerableItem(detail_issues :pd.DataFrame) -> bool:
    print(f"#6. create_csv_for_field_map_VulnerableItem")
    # convert field mapping
    detail_issues["id"] = detail_issues["entity_name"]

    # extract servicenow field 
    out = pd.DataFrame()
    for snow_key,asm_key in field_map_VulnerableItem.items() :
        if asm_key in detail_issues.keys():
            out[snow_key] = detail_issues[asm_key]
        else:
            print(f"\t{snow_key}  {asm_key} - NG")

    # save
    out.to_csv("./6_VulnerableItem.csv", index = False)    
    return True

# ------------------------------------------------------------
def main():
    print("Start")
    project_id = 25821
    collection_name = ""  # all collectiions in the project
    # collection_name = "kiri-test_ycntoqu" 

    # # data loading - collections
    project_name = asm.get_project_name(project_id)
    collections_df = asm.get_collections(project_id) 
    collections_df.to_csv("collections_df.csv")
     
    # # # data loading - issues 
    search_query = f"status_new:open"
    issues_df = asm.search_data(project_id=project_id,collectionName=collection_name,type="issue",query=search_query)
    issues_df.to_csv("issues_df.csv")

    # # # data loading - issues detail
    detail_issues_df = asm.get_detail_issues(issues_df["id"].to_list() )
    detail_issues_df = asm.decompress_nested_items_in_issue_details(detail_issues_df)
    detail_issues_df["project_id"]   = project_id
    detail_issues_df["project_name"] = project_name
    detail_issues_df.to_csv(f"detail_issues_df-{collection_name}.csv")

    # create csv files 
    create_csv_for_VulnerableItemDetection(detail_issues_df) #1
    create_csv_for_MandiantASMProjectsAndCollectionsConfiguration(collections_df) #2
    create_csv_for_NationalVulnerabilityDatabaseEntry(detail_issues_df) #3
    create_csv_for_ThirdPartyVulnerabilityEntry(detail_issues_df) #4
    create_csv_for_VulnerabilitySolution(detail_issues_df) #5
    create_csv_for_field_map_VulnerableItem(detail_issues_df) #6

    print("Finsihed!")
    return 

# ------------------------------------------------------------
if __name__ == "__main__":
    # asm.show_project_list()
    main()