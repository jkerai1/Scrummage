#!/usr/bin/env python3

import os, re, logging, requests, urllib.parse, plugins.common.General as General

Plugin_Name = "NZ-Business"
Concat_Plugin_Name = "nzbusiness"
The_File_Extension = ".html"

def Search(Query_List, Task_ID, Type, **kwargs):
    Data_to_Cache = []
    Cached_Data = []

    Directory = General.Make_Directory(Concat_Plugin_Name)

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    Log_File = General.Logging(Directory, Concat_Plugin_Name)
    handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    Cached_Data = General.Get_Cache(Directory, Plugin_Name)

    if not Cached_Data:
        Cached_Data = []

    Query_List = General.Convert_to_List(Query_List)

    for Query in Query_List:

        try:

            if Type == "NZBN":
                Main_URL = 'https://app.companiesoffice.govt.nz/companies/app/ui/pages/companies/search?q=' + Query + '&entityTypes=ALL&entityStatusGroups=ALL&incorpFrom=&incorpTo=&addressTypes=ALL&addressKeyword=&start=0&limit=1&sf=&sd=&advancedPanel=true&mode=advanced#results'
                Response = requests.get(Main_URL).text

                try:

                    if 'An error has occurred and the requested action cannot be performed.' not in Response:
                        Query = str(int(Query))

                        if Main_URL not in Cached_Data and Main_URL not in Data_to_Cache:
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Response, General.Get_Title(Main_URL), The_File_Extension)

                            if Output_file:
                                General.Connections(Output_file, Query, Plugin_Name, Main_URL, "app.companiesoffice.govt.nz", "Data Leakage", Task_ID, General.Get_Title(Main_URL), Plugin_Name)
                                Data_to_Cache.append(Main_URL)

                except:
                    logging.warning(General.Date() + " - " + __name__ + " - Invalid query provided for NZBN Search.")

            elif Type == "NZCN":

                if kwargs.get('Limit'):

                    if int(kwargs["Limit"]) > 0:
                        Limit = kwargs["Limit"]

                else:
                    Limit = 10

                try:
                    Main_URL = 'https://app.companiesoffice.govt.nz/companies/app/ui/pages/companies/search?q=' + urllib.parse.quote(
                        Query) + '&entityTypes=ALL&entityStatusGroups=ALL&incorpFrom=&incorpTo=&addressTypes=ALL&addressKeyword=&start=0&limit=' + str(
                        Limit) + '&sf=&sd=&advancedPanel=true&mode=advanced#results'
                    Response = requests.get(Main_URL).text
                    NZCN_Regex = re.search(r".*[a-zA-Z].*", Query)

                    if NZCN_Regex:
                        General.Main_File_Create(Directory, Plugin_Name, Response, Query, The_File_Extension)
                        NZBNs_Regex = re.findall(r"\<span\sclass\=\"entityName\"\>([\w\d\s\-\_\&\|\!\@\#\$\%\^\*\(\)\.\,]+)\<\/span\>\s<span\sclass\=\"entityInfo\"\>\((\d{6})\)\s\(NZBN\:\s(\d{13})\)", Response)

                        if NZBNs_Regex:

                            for NZCN, NZ_ID, NZBN_URL in NZBNs_Regex:
                                print(NZBN_URL, NZ_ID, NZCN)
                                Full_NZBN_URL = 'https://app.companiesoffice.govt.nz/companies/app/ui/pages/companies/' + NZ_ID + '?backurl=H4sIAAAAAAAAAEXLuwrCQBCF4bfZNtHESIpBbLQwhWBeYNgddSF7cWai5O2NGLH7zwenyHgjKWwKGaOfSwjZ3ncPaOt1W9bbsmqaamMoqtepnzIJ7Ltu2RdFHeXIacxf9tEmzgdOAZbuExh0jknk%2F17gRNMrsQMjiqxQmsEHr7Aycp3NfY5PjJbcGSMNoDySCckR%2FPwNLgXMiL4AAAA%3D'

                                if Full_NZBN_URL not in Cached_Data and Full_NZBN_URL not in Data_to_Cache:
                                    Current_Response = requests.get(Full_NZBN_URL).text
                                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, str(Current_Response), NZCN.replace(' ', '-'), The_File_Extension)

                                    if Output_file:
                                        General.Connections(Output_file, Query, Plugin_Name, Full_NZBN_URL, "app.companiesoffice.govt.nz", "Data Leakage", Task_ID, General.Get_Title(Full_NZBN_URL), Plugin_Name)
                                        Data_to_Cache.append(Full_NZBN_URL)

                        else:
                            logging.warning(General.Date() + " - " + __name__ + " - Response did not match regular expression.")

                    else:
                        logging.warning(General.Date() + " - " + __name__ + " - Query did not match regular expression.")

                except:
                    logging.warning(General.Date() + " - " + __name__ + " - Invalid query provided for NZCN Search.")

            else:
                logging.warning(General.Date() + " - " + __name__ + " - Invalid request type.")

        except:
            logging.warning(General.Date() + " - " + __name__ + " - Failed to make request.")

    if Cached_Data:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "a")

    else:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "w")