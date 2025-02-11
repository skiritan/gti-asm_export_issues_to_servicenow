import os
import requests
import pprint

import json
import pandas as pd
import ast

# ------------------------------------------------------------
# API Endpoint list - as of 2025/02/07 for GTI
baseUrl = "https://www.virustotal.com"
projectsEndPoint="/api/v3/asm/projects"
collectionsEndPoint="/api/v3/asm/user_collections/"
entitiesEndPoint ="/api/v3/asm/search/entities/"
entitiydetailEndPoint= "/api/v3/asm/entities/"
issuesEndPoint="/api/v3/asm/search/issues/"
techEndPoint="/api/v3/asm/search/technologies/"
issuesLibraryEndpoint="/api/v3/asm/library/issues"

# ------------------------------------------------------------
def _get_headers(project_id:int=0) -> dict:
    ApiKey = os.getenv('GTI_API_KEY')
    # APIKey - GTI Console > Profile > API > 
    # ApiKey = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    headers = {"accept": "application/json","X-Apikey": ApiKey }
    
    if project_id != 0:
        headers["PROJECT-ID"]= str(project_id) # for gti-api
    return headers

# ------------------------------------------------------------
def show_project_list():
    _headers =  _get_headers()
    url = "https://www.virustotal.com/api/v3/asm/projects"
    # response = requests.get(url , headers=_headers)
    response=requests.get((baseUrl+projectsEndPoint), headers= _headers)
    res = json.loads(response.text)
    print( [ f"{c['id']} {c['name']}" for c in res["result"]] )
    return ""

# ------------------------------------------------------------
def get_project_name(project_id:int)->str:
    project_df = get_projects()
    return project_df[ project_df["id"]==project_id]["name"].iloc[0]

# ------------------------------------------------------------
def get_projects() -> str:
    _headers =  _get_headers()
    url = "https://www.virustotal.com/api/v3/asm/projects"
    response=requests.get((baseUrl+projectsEndPoint), headers= _headers)
    projects_df = pd.DataFrame.from_records(response.json()['result'])
    return projects_df

# ------------------------------------------------------------
def get_collections(project_id:int) -> pd.DataFrame:
    _headers =  _get_headers(project_id)
    baseUrl = "https://www.virustotal.com/api/v3/asm/"
    collectionsEndPoint = "user_collections"
    response=requests.get((baseUrl+collectionsEndPoint), headers= _headers)
    collections_df = pd.DataFrame.from_records(response.json()['result'])
    # print(response.json())
    return collections_df

# ------------------------------------------------------------
# search entity/issue/tech data with query string.
def search_data(project_id:int,collectionName:str,type:str, query:str, silent:bool=False) -> pd.DataFrame:
    page_size = 1000
    _headers = _get_headers(project_id)

    api_endpoint ={
        "entity" : entitiesEndPoint,
        "issue" : issuesEndPoint,
        "tech" : techEndPoint,
    }
    search_query = query + "?page_size=" + str(page_size)
    if collectionName != "":
        search_query = "collection:" + collectionName + " " + search_query 

    print(f"Searching {type} data...",end="") if not silent else ""
    response=requests.get((baseUrl+api_endpoint[type] +search_query),headers=_headers)
    if response.status_code != 200:
        print(f"{response=},{search_query=}")
        return False # TASK: raise exception.
 
    total_pages = response.json()['result']['total_pages']
    data_df = pd.DataFrame.from_records(response.json()['result']['hits'])

    page = 1
    if total_pages > 1:
        while total_pages > page:
            print(f"\rSearching {type} data... {page}/{total_pages}, Count:{len(data_df)} ",end="") if not silent else ""
            response=requests.get((baseUrl+api_endpoint[type]+ search_query+"&page="+str(page)), headers=_headers)
            data_temp = pd.DataFrame.from_records(response.json()['result']['hits'])
            data_df = pd.concat([data_df,data_temp])
            page=page+1

    print(f"\rSearching {type} data... {page}/{total_pages}, Count:{len(data_df)}") if not silent else ""
    data_df = data_df.reset_index(drop=True)
    if len(data_df) ==10000:
        print("[Alert] data count: 10000 ")
    return data_df


# ------------------------------------------------------------
def get_detail_issues(issues_id:list) -> pd.DataFrame:
    _headers = _get_headers()
    res =[]          
    for i,id in enumerate(issues_id):
        print(f"\rDownloading issues details... {i}/{len(issues_id)} ",end="")        
        url = f"https://www.virustotal.com/api/v3/asm/issues/{id}"
        response = requests.get(url, headers=_headers)
        if response.status_code != 200:
            print(f"status_code 200: {response=}")
            return "" # TASK: raise exception.
        issues_detail = response.json()['result']
        res.append(issues_detail)

    print(f"\rDownloading issues details... {len(issues_id)} - completed! ")        
    return pd.DataFrame(res)

# ------------------------------------------------------------
def _decompress_nested_items(items,key:str):
    match items:
        case None:
            return "None"
        case dict():
            return items[key] if key in items.keys() else "None"

        case str():
            # print(f"{key} - {type(items)}:  {items}")
            d = ast.literal_eval(items)
            if d == None:
                return ""
            return d[key] if key in d.keys() else "None"

        case list():
            return ",".join([i[key] for i in items]) if items else "None"

        case float():
            print(f"match:flat - {type(items)}")
            print(f"{key} - {type(items)}:  {items}")
            if items ==  float('nan'):
                return "" 
        case _:
            print(f"undefined type in decompress_nested_items - {type(items)}")
            print(f"{key} - {type(items)}:  {items}")
            return "None"    

# ------------------------------------------------------------
def decompress_nested_items_in_issue_details(df:pd.DataFrame) -> pd.DataFrame:
    nested_items = [
        "details/added",
        "details/affected_software",
        "details/category",
        "details/description",
        "details/name",
        "details/remediation",
        "details/pretty_name",
        "details/proof",
        "details/severity",
        "details/vendor",
        "summary/status",
        "summary/status_new",
        "summary/pretty_name",
        "identifiers/name",
    ]

     # decompress nested_dict_strings
    for item in nested_items:
        parent = item.split("/")[0]
        child =  item.split("/")[1]
        df[item] = [ _decompress_nested_items(t,child) for t in df[parent] ]

    # for specific items
    df["_vendor"] = [ _decompress_nested_items(t,"vendor") for t in df["details/affected_software"] ]

    return df

# ------------------------------------------------------------
def get_issue_detail(issue_id:str) -> pd.Series:
    _headers = _get_headers()
    url = f"https://www.virustotal.com/api/v3/asm/issues/{issue_id}"
    response = requests.get(url, headers=_headers)
    dat = response.json()['result']
    return pd.Series(dat)

# ------------------------------------------------------------
def get_issue_library() -> pd.DataFrame:
    _headers = _get_headers()
    response=requests.get((baseUrl+issuesLibraryEndpoint),headers=_headers)
    issuesLib_df = pd.DataFrame.from_records(response.json()['result'])
    more = response.json()['more']
    count = 1
    while more == True:
        response=requests.get((baseUrl+issuesLibraryEndpoint+"?page="+str(count)),headers=_headers)
        issuesLib_temp = pd.DataFrame.from_records(response.json()['result'])
        issuesLib_df = pd.concat([issuesLib_df,issuesLib_temp])
        more = response.json()['more']
        count=count+1
    return issuesLib_df