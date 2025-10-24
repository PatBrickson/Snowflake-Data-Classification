create secret if not exists BRICKSON_SECRET
    TYPE=password
    USERNAME = ''
    PASSWORD = '';

CREATE OR REPLACE PROCEDURE BRICKSON_CLASSIFY_PROCEDURE()
RETURNS STRING
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('requests','snowflake-snowpark-python')
HANDLER = 'BRICKSON_CLASSIFY'
EXTERNAL_ACCESS_INTEGRATIONS = (EXTERNAL_ACCESS)
SECRETS = ('BRICKSON_SECRET' = BRICKSON_SECRET)
EXECUTE AS CALLER
AS
$$
# This information is built by assinging a Snowflake classification profile to a schema.
# The profile specifies how frequently it should be re-checked.  We should not need to worry
# about manually re-scanning information.  Snowflake will take care of this for us.

import json
import requests
import time
import re
import _snowflake
from datetime import datetime
from snowflake.snowpark import Session
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Any

logging_procedure_name = "BRICKSON_CLASSIFY_PROCEDURE"
logging_success = "SUCCESS"
logging_informational = "INFORMATIONAL"
logging_error = "ERROR"
logging_warning = "WARNING"

secret_name = "BRICKSON_SECRET"
alation_url  = "https://PB.alationcloud.com"
alation_Oauth_name = "data_integrity_coe_sa"

ClassificationLookup = Dict[Tuple[str, str], Dict[str, str]]
FieldIdLookup = Dict[str, int]

CustomFieldNameList = [
    "Special Handling Flag",
    "Special Handling Reason",
    "PB Data Classification Category",
    "PB Data Classification Level",
    "PB Data Classification Number",
    "PB Data Classification Type",
    "Snowflake Data Classification Category",
    "Snowflake Data Classification Type"
]

MAX_ALATION_COLUMNS_PAYLOAD = 10000

@dataclass
class CustomField:
    field_name: str = ""
    field_id: int = 0
    value: str = ""
    
@dataclass
class ClassificationElement:
    database: str = ""
    schema: str = ""
    table: str = ""
    column: str = ""
    ds_id: int = 0
    schema_id: int = 0
    table_id: int = 0
    column_id: int = 0
    privacy_category: str = ""
    semantic_category: str = ""
    custom_fields: List[CustomField] = field(default_factory=list)

@dataclass
class PayloadElement:
    id: int = 0
    custom_fields: List[CustomField] = field(default_factory=list)

###########################################################################################################
# Procedure remove_html_tags
#   Purpose: Use Regular Expressions to remove HTML tags from the input string.
#   Input:
#       - Text - String that needs to be cleaned
#   Ouput: A copy of the input string with HTML tags removed
###########################################################################################################

def remove_html_tags(
        text: str
    ) -> str:

    clean = re.compile('<.*?>')
    return re.sub(clean, '', text)


###########################################################################################################
# Procedure log_message
#   Purpose: Write messages to a logging table in Snowflake.  This is done to improve trouble shooting.
#   Input:
#       - Session - Active Snowflake session
#       - log_level - Type of message being logged: Success, Informational, Warning, Error
#       - message - String that will be written to the logging table
###########################################################################################################

def log_message(
        session: Session,
        log_level: str,
        message: str):

    current_dt = datetime.now()
    insert_sql = f"""INSERT INTO 
                        brickson_logging_table 
                        (timestamp, procedure_name, log_level, message) 
                        VALUES (TO_TIMESTAMP('{current_dt}'), '{logging_procedure_name}', '{log_level}', '{message}')"""

    session.sql(insert_sql).collect()


###########################################################################################################
# Procedure authenticate_alation
#   Purpose: Generate a JSON Web token which will be used to authenticate calls to Alation.  Note that the
#            passphrase needed to obtain this token is stored in a Secret object within Snowflake.
#   Input:
#       - Session - Active Snowflake session
#   Output:
#       - A string containing the JSON web token
###########################################################################################################

def authenticate_alation(
        session: Session
    ) -> str:

    username_object = _snowflake.get_username_password(secret_name)
    alation_client_id = username_object.username
    alation_client_secret = username_object.password

    url = f"{alation_url}/oauth/v2/token/"
    payload = {
        "grant_type": "client_credentials",
        "client_id": alation_client_id,
        "client_secret": alation_client_secret
    }
    headers = {
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded"
    }

    try:
        response = requests.post(url, headers=headers, data=payload, verify=False)

    except Exception as e:
        raise RuntimeError(f"Failed to fetch OAuth token: {e}")

    if response.status_code != 200:
        raise RuntimeError(f"API call to fetch OAuth token failed. Status: {response.status_code}, Response: {response.text}")


    api_access_token = response.json().get("access_token")

    return api_access_token


###########################################################################################################
# Procedure build_custom_field_id_lookup
#   Purpose: Read the list of custom fields that exist in the Alation instance and build a Python dictionary
#            containing the field name and the field_id.  The field_id is needed when writing back to Alation.
#   Input:
#       - Access_token - JSON web token used to authenticate Alation connection
#   Output:
#       - A Python dictionary which will allow field_id lookup by custom field name
###########################################################################################################

def build_custom_field_id_lookup(
        access_token: str
    ) -> FieldIdLookup:

    records_read = 0
    records_per_call = 100
    field_lookup = {}

    url = f"{alation_url}/integration/v2/custom_field/"
    headers = {
        "Authorization": f"Bearer {access_token}", 
        "Content-Type": "application/json"
    }

    while True:
        params = {'limit': records_per_call, 'skip': records_read}

        try:
            response = requests.get(url, params=params,headers=headers)

        except Exception as e:
            raise RuntimeError("Error reading custom field list from Alation: {e}")

        if response.status_code != 200:
            raise RuntimeError(f"API call to read custom field list from Alation failed. Status: {response.status_code}, Response: {response.text}")

        alation_json = response.json()

        if len(alation_json) == 0:
            #no more records to process
            break

        for row in alation_json:
            field_lookup[row["name_singular"]] = row["id"]
            records_read += 1
                
    return field_lookup


###########################################################################################################
# Procedure build_PB_classifications_lookup
#   Purpose: Read the classification "rules" table from Snowflake.  This table maps Snowflake classification
#            tags to PB classification values.  Create a Python dictionary that will allow lookup of PB
#            values based on the Snowflake values.
#   Input:
#       - Session - Active Snowflake session
#   Output:
#       - A python dictionary that will allow lookup of PB classification values based on the Snowflake 
#         classification values.
###########################################################################################################

def build_PB_classifications_lookup(
        session: Session
    ) -> ClassificationLookup:

    classification_lookup = {}
    df = session.table("PB_DATA_CLASSIFICATION_MAPPING")

    try:
        rows = df.collect()

    except Exception as e:
        raise RuntimeError(f"Fatal error reading PB_DATA_CLASSIFICATION_MAPPING: {str(e)}")

    #Note that the names listed below are designed to match the column names returned from the Alation API

    classification_lookup = {
        (row["SF_PRIVACY_CATEGORY"],row["SF_SEMANTIC_CATEGORY"]): {
                "PB Data Classification Number": row["PB_DATA_CLASSIFICATION_NUM"],
                "PB Data Classification Level": row["PB_DATA_CLASSIFICATION_LEVEL"],
                "PB Data Classification Type": row["PB_DATA_CLASSIFICATION_TYPE"],
                "PB Data Classification Category": row["PB_DATA_CLASSIFICATION_CATEGORY"],
                "Special Handling Flag": row["SPECIAL_HANDLING_FLAG"],
                "Special Handling Reason": row["SPECIAL_HANDLING_REASON"],
                "Snowflake Data Classification Category": row["SF_PRIVACY_CATEGORY"],
                "Snowflake Data Classification Type": row["SF_SEMANTIC_CATEGORY"]}
        for row in rows
    }

    return classification_lookup

###########################################################################################################
# Procedure get_classification_rows
#   Purpose: Read the classification values that have been assigned by the Snowflake data classification
#            profile.
#   Input:
#       - Session - Active Snowflake session
#       - fld_lookup - A Python dictionary that will allow lookup of Alation custom field ids
#   Output:
#       - A list of Snowflake columns that have been assigned a classification value by the Snowflake
#         classification profile.  Known fields will be filled in, the rest will be set to default values
#         which will be filled in later.
###########################################################################################################

def get_classification_rows(
        session: Session,
        fld_lookup: FieldIdLookup
    ) -> List[ClassificationElement]:

    sf_list = []
    sql_string = f"""
            SELECT
                database_name,
                schema_name,
                table_name,
                column_name,
                privacy_category,
                semantic_category
            FROM
                PB_DATA_CLASSIFICATIONS_VW
            WHERE privacy_category IS NOT NULL"""

    try:
        row_list = session.sql(sql_string).collect()

    except Exception as e:
        raise RuntimeError(f"Reading from PB_DATA_CLASSIFICATIONS_VW: {e}")


    for r in row_list:

        # Build the list of CustomField objects using fld_lookup. We are pre-populating custom_fields 
        # with all of the column names from Alation as well as the corresponding field_id.  Values will
        # be filled in later.

        custom_field_list = []
        for name in CustomFieldNameList:
            field_id = fld_lookup.get(name, 0)  # Default to 0 if not found
            custom_field = CustomField(field_name=name, field_id=field_id)
            custom_field_list.append(custom_field)

        sf_item = ClassificationElement(
            database = r['DATABASE_NAME'],
            schema = r['SCHEMA_NAME'],
            table = r['TABLE_NAME'],
            column = r['COLUMN_NAME'],
            privacy_category = r['PRIVACY_CATEGORY'],
            semantic_category = r['SEMANTIC_CATEGORY'],
            custom_fields = custom_field_list
        )

        sf_list.append(sf_item)


    return sf_list


###########################################################################################################
# Procedure get_table_from_alation
#   Purpose: Read a table object from Alation based on the schema and table name passed in sf_element.
#            Enrich sf_element with ds_id, schema_id, & table_id from Alation.
#   Input:
#       - Session - Active Snowflake session
#       - Access_token - JSON web token used to authenticate Alation connection
#       - sf_element - an object of class ClassificationElement
#   Output:
#       - The number of items processed
###########################################################################################################

def get_table_from_alation(
        session: Session,
        access_token: str,
        sf_element: ClassificationElement
    ) -> int:

    elements_processed = 0

    url = f"{alation_url}/integration/v2/table/?name={sf_element.table}&schema_name={sf_element.database}.{sf_element.schema}"
    headers = {
        "Authorization": f"Bearer {access_token}", 
        "Content-Type": "application/json"
    }

    try:
        response = requests.get(url, headers=headers)

    except Exception as e:
        raise RuntimeError("Error reading table from Alation: {e}")

    if response.status_code != 200:
        raise RuntimeError(f"API call to read table from Alation failed. Status: {response.status_code}, Response: {response.text}")

    alation_json = response.json()[0]

    if len(alation_json) > 0:
        sf_element.ds_id = alation_json.get("ds_id")
        sf_element.schema_id = alation_json.get("schema_id")
        sf_element.table_id = alation_json.get("id")
        elements_processed += 1
    else:
        log_message(
            session, 
            logging_informational,
            f"{sf_element.database}.{sf_element.schema}.{sf_element.table} does not exist in Alation")
                
    return elements_processed

###########################################################################################################
# Procedure get_column_from_alation
#   Purpose: Read a column object from Alation based on the ds_id, schema_id, table_id, and column name
#            passed in sf_element.  Enrich sf_element by adding column_id and a list of custom fields that
#            are associated with the column.
#   Input:
#       - Session - Active Snowflake session
#       - Access_token - JSON web token used to authenticate Alation connection
#       - sf_element - an object of class ClassificationElement
#       - cls_lookup - A Python dictionary that will allow lookup of PB classification values
#   Output:
#       - A string containing the JSON web token
###########################################################################################################

def get_column_from_alation(
        session: Session,
        access_token: str,
        sf_element: ClassificationElement
    ) -> int:

    elements_processed = 0

    url = f"{alation_url}/integration/v2/column/?name={sf_element.column}&schema_id={sf_element.schema_id}&table_id={sf_element.table_id}"
    headers = {
        "Authorization": f"Bearer {access_token}", 
        "Content-Type": "application/json"
    }

    try:
        response = requests.get(url, headers=headers)

    except Exception as e:
        raise RuntimeError(f"Error reading column from Alation: {e}")


    if response.status_code != 200:
        raise RuntimeError(f"API call to read column from Alation failed. Status: {response.status_code}, Response: {response.text}")

    alation_json = response.json()[0]

    if len(alation_json) > 0:
 
        elements_processed += 1
        
        sf_element.column_id = alation_json.get("id")

        # Step 1: Build a lookup from Alation custom_fields
        alation_fields = alation_json.get("custom_fields", [])
        alation_field_map = {cf["field_name"]: cf["value"] for cf in alation_fields}


        # Step 2: Update sf_element.custom_fields with values from Alation
        for cf in sf_element.custom_fields:
            if cf.field_name in alation_field_map:
                cf.value = remove_html_tags(alation_field_map[cf.field_name])

    else:
        log_message(
            session, 
            logging_informational,
            f"{sf_element.database}.{sf_element.schema}.{sf_element.table}.{sf_element.column} does not exist in Alation")
        
    return elements_processed

###########################################################################################################
# Procedure get_alation_values
#   Purpose: Generate a JSON Web token which will be used to authenticate calls to Alation.  Note that the
#            passphrase needed to obtain this token is stored in a Secret object within Snowflake.
#   Input:
#       - Session - Active Snowflake session
#   Output:
#       - A string containing the JSON web token
###########################################################################################################

def get_alation_values(
        session: Session,
        access_token: str,
        sf_list: List[ClassificationElement]
    ) -> List[ClassificationElement]:


    for s in sf_list:

        try:
            rows_processed = get_table_from_alation(
                                    session,
                                    access_token,
                                    s)

        except RuntimeError as e:
            raise e


        if (rows_processed > 0):
            try:
                columns_processed = get_column_from_alation(
                                    session,
                                    access_token,
                                    s)

            except RuntimeError as e:
                raise e

        # Delay added to prevent Alation timeouts.  Without this, the API calls sporadically fail.
        time.sleep(0.3)

    return sf_list

###########################################################################################################
# Procedure build_update_list
#   Purpose: Generate a JSON Web token which will be used to authenticate calls to Alation.  Note that the
#            passphrase needed to obtain this token is stored in a Secret object within Snowflake.
#   Input:
#       - Session - Active Snowflake session
#   Output:
#       - A string containing the JSON web token
###########################################################################################################

def build_update_list(
    session: Session,
    sf_list: List[ClassificationElement],
    PB_mapping: ClassificationLookup
) -> List[ClassificationElement]:

    update_list = []

    for s in sf_list:
        key = (s.privacy_category, s.semantic_category)
        lookup_val = PB_mapping.get(key)

        if not lookup_val:
            log_message(
                session, 
                logging_informational,
                f"Privacy category: {s.privacy_category}  Semantic category: {s.semantic_category} does not exist in PB lookup table"
            )
            continue

        changed_fields=[]

        for cf in s.custom_fields:
            if cf.field_name in lookup_val and cf.value == "" and lookup_val[cf.field_name] is not None:
                if isinstance(lookup_val[cf.field_name], str):
                    new_value = remove_html_tags(lookup_val[cf.field_name])
                else:
                    new_value = lookup_val[cf.field_name]

                changed_fields.append(
                    CustomField(
                        field_name = cf.field_name,
                        field_id = cf.field_id,
                        value = new_value
                    )
                )

        if changed_fields:
            updated_element = s
            updated_element.custom_fields = changed_fields
            update_list.append(updated_element)

    return update_list

###########################################################################################################
# Procedure update_alation_records
#   Purpose: Generate a JSON Web token which will be used to authenticate calls to Alation.  Note that the
#            passphrase needed to obtain this token is stored in a Secret object within Snowflake.
#   Input:
#       - Session - Active Snowflake session
#   Output:
#       - A string containing the JSON web token
###########################################################################################################

def update_alation_records(
    session: Session,
    access_token: str,
    update_list: List[ClassificationElement]
) -> List[Dict[str, Any]]:

    url = f"{alation_url}/integration/v2/column/"
    headers = {
        "Authorization": f"Bearer {access_token}", 
        "Accept": "application/json",
        "Content-Type": "application/json"}
        
    items_updated = 0

    # List of items that will be sent to alation to update
    payload_list = []

    # Helper dictionary to track existing payload elements by ds_id
    payload_map = Dict[int, List[Dict[str, Any]]] = {}

    # Build the payload list.  Note that there will be at least one element per ds_id, each element consisting
    # of a list of columns to be updated.  We can have a maximum of 10,000 column objects in the payload for
    # this API so there could be more than one element per ds_id.

    for col_element in update_list:
        ds_id = col_element.ds_id
        column_payload = {
            "column_id": col_element.column_id,
            "custom_fields": [
                {"field_id": cf.field_id, 
                 "value": cf.value} 
                 for cf in col_elment.custom_fields]
        }

        if ds_id not in payload_map:
            payload_map[ds_id] = []
        payload_map[ds_id].append(column_payload)

        # Split into chunks of 10,000 colums per ds_id
        for ds_id, columns in payload_map.items():
            for i in range(0, len(columns), MAX_COLUMNS):
                chunk = columns[i: i + MAX_COLUMNS]
                payload_list.append(
                    {
                        "ds_id":ds_id,
                        "columns":chunk
                    }
                )

    return payload_list


#    try:
#        response = requests.get(url, headers=headers)

#    except Exception as e:
#        raise RuntimeError("Error reading column from Alation: {e}")


#    if response.status_code != 200:
#        raise RuntimeError(f"API call to read column from Alation failed. Status: {response.status_code}, Response: {response.text}")

#    column_json = response.json()[0]

#    if len(column_json) > 0:
#        columns_processed = 1
#        table_element["ALATION_COLUMN_ID"] = column_json.get("id")
#        for field in column_json["custom_fields"]:
#            match field:
#                case "Data Classification_Level":
#                    table_element["ALATION_CLASSIFICATION_LEVEL"] = field["value"]

#                case "Data Classification_Type":
#                    table_element["ALATION_CLASSIFICATION_TYPE"] = field["value"]

#                case "Data Classification_Category":
#                    table_element["ALATION_CLASSIFICATION_CATEGORY"] = field["value"]
#    else:
#        log_message(
#            session, 
#            logging_informational,
#            f"{database_name}.{schema_name}.{table_name}.{column_name} does not exist in Alation")
        

    return rows_processed


###########################################################################################################
#
# Main procedure
#
###########################################################################################################

def BRICKSON_CLASSIFY(session):

    log_message(session, logging_informational, f"Beginning run")

# Build a Python dictionary that will serve as a lookup of the master Snowflake -> PB data 
# classification get_PB_classification_mappings.

    try:
        cls_lookup = build_PB_classifications_lookup(session)

    except RuntimeError as e:
        error_string = f"Error returned from get_PB_classification_mappings: {e}"
        log_message(session, logging_error, error_string)
        raise RuntimeError(error_string)


# Connect to Alation and obtain a web token that will be used for connecting to Alation via api_access_token

    try:
        alation_token = authenticate_alation(session)

    except RuntimeError as e:
        error_string = f"Error returned from authenticate_alation: {e}"
        log_message(session, logging_error, error_string)
        raise RuntimeError(error_string)


# Get the list of custom fields from Alation.  Needed to obtain field_id which is needed for update calls.

    try:
        field_id_lookup = build_custom_field_id_lookup(alation_token)

    except RuntimeError as e:
        error_string = f"Error returned from get_classification_rows: {e}"
        log_message(session, logging_error, error_string)
        raise RuntimeError(error_string)


# Read classification information from Snowflake.

    try:
        sf_list = get_classification_rows(session, field_id_lookup)

    except RuntimeError as e:
        error_string = f"Error returned from get_classification_rows: {e}"
        log_message(session, logging_error, error_string)
        raise RuntimeError(error_string)


# Take the classification information read from Snowflake and pass to Alation to determine
# whether the catalog page needs to be modified.

    try:
        full_classification_list = get_alation_values(session, alation_token, sf_list)

    except RuntimeError as e:
        error_string = f"Error returned from add_alation_ids: {e}"
        log_message(session, logging_error, error_string)
        raise RuntimeError(error_string)


# Determine which objects within Snowflake need to be modified.

    try:
        update_list = build_update_list(session, full_classification_list, cls_lookup)

    except RuntimeError as e:
        error_string = f"Error returned from build_update_list: {e}"
        log_message(session, logging_error, error_string)
        raise RuntimeError(error_string)


# Update fields in Alation.

    try:
        payload_list = update_alation_records(session, alation_token, update_list)

    except RuntimeError as e:
        error_string = f"Error returned from update_alation_records: {e}"
        log_message(session, logging_error, error_string)
        raise RuntimeError(error_string)

    return payload_list

    log_message(session, 
                logging_success,
                f"Completed successfully")

    return "Success"

$$;

--GRANT OWNERSHIP ON SECRET POWERBI_SERVICE_SECRET_ID TO DATABASE ROLE RAW_POWERBI_ACCESS_FULL COPY CURRENT GRANTS;
--GRANT OWNERSHIP ON SECRET POWERBI_SERVICE_CLIENT_ID TO DATABASE ROLE RAW_POWERBI_ACCESS_FULL COPY CURRENT GRANTS;
