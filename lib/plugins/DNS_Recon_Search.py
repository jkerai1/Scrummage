#!/usr/bin/env python3
import plugins.common.General as General, plugins.common.checkdmarc as checkdmarc, json, os, logging

The_File_Extension = ".json"
Plugin_Name = "DNS-Recon"
Concat_Plugin_Name = "dnsrecon"

def Search(Query_List, Task_ID):
    Data_to_Cache = []
    Cached_Data = []
    Directory = General.Make_Directory(Concat_Plugin_Name)

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    Log_File = General.Logging(Directory, Plugin_Name.lower())
    handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    Cached_Data = General.Get_Cache(Directory, Plugin_Name)

    if not Cached_Data:
        Cached_Data = []

    Query_List = General.Convert_to_List(Query_List)

    try:
        DNS_Info = checkdmarc.check_domains(Query_List)

        if len(Query_List) > 1:

            for DNS_Item in DNS_Info:
                Query = DNS_Item['base_domain']
                Output_Dict = json.dumps(DNS_Item, indent=4, sort_keys=True)
                Link = "https://www." + Query
                Title = "DNS Information for " + DNS_Item['base_domain']

                if Link not in Data_to_Cache and Link not in Cached_Data:
                    Output_file = General.Main_File_Create(Directory, Plugin_Name, Output_Dict, Query, The_File_Extension)

                    if Output_file:
                        Output_Connections = General.Connections(Query, Plugin_Name, Query, "Domain Spoof", Task_ID, Concat_Plugin_Name)
                        Output_Connections.Output(Output_file, Link, Title)

                    Data_to_Cache.append(Link)

        else:
            Query = DNS_Info['base_domain']
            Output_Dict = json.dumps(DNS_Info, indent=4, sort_keys=True)
            Link = "https://www." + Query
            Title = "DNS Information for " + Query

            if Link not in Data_to_Cache and Link not in Cached_Data:
                Output_file = General.Main_File_Create(Directory, Plugin_Name, Output_Dict, Query, The_File_Extension)

                if Output_file:
                    Output_Connections = General.Connections(Query, Plugin_Name, Query, "Domain Spoof", Task_ID, Concat_Plugin_Name)
                    Output_Connections.Output(Output_file, Link, Title)

                Data_to_Cache.append(Link)

    except:
        logging.warning(General.Date() + " - " + __name__.strip('plugins.') + " - Error retrieving DNS details.")

    if Cached_Data:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "a")

    else:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "w")
