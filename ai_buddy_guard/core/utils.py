# Standard library imports
import json
import logging
import os
import re
import shutil
import subprocess
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse

# Third-party imports
import requests
from botocore.exceptions import BotoCoreError, ClientError
from git import Repo
from git.exc import GitCommandError
from github import Github
from bs4 import BeautifulSoup
from langchain.chat_models import ChatOpenAI
from langchain.schema import HumanMessage

# Local module imports

# Initialize logging
logging.basicConfig(level=logging.INFO)

def scan_git_secrets(git_url: str) -> str:
    """Scans a git repository for leaked secrets.

    Args:
        git_url (str): The URL of the git repository to scan. Format should be 'https://github.com/username/repository_name.git'.

    Returns:
        str: A JSON-formatted string containing any leaked secrets. Returns an empty string if no secrets are found.
    """
    repo_url = git_url
    result = subprocess.run(['trufflehog', '--regex', '--entropy=False', repo_url, '--json'], stdout=subprocess.PIPE)
    result = result.stdout.decode('utf-8')
    lines = result.splitlines()

    json_objs = []  # Initialize json_objs as an empty list
    for line in lines:
        json_obj = json.loads(line)
        
        # Remove 'diff' and 'printDiff' from the object
        json_obj.pop('diff', None)
        json_obj.pop('printDiff', None)
        
        json_objs.append(json_obj)  # Append each json_obj to the list

    # Convert it back to JSON and print
    return(json.dumps(json_objs, indent=4))


def extract_info(data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Extracts relevant information from the data.

    Args:
        data (list): The data to extract information from.

    Returns:
        list: A list of dictionaries containing the extracted information.
    """
    info = []
    for alert in data:
        alert_info = {
            'Number': alert.get('number'),
            'State': alert.get('state'),
            'Dependency': alert.get('dependency', {}).get('package', {}).get('name'),
            'Security Advisory': alert.get('security_advisory', {}).get('ghsa_id'),
            'Severity': alert.get('security_vulnerability', {}).get('severity'),
            'Vulnerable Version Range': alert.get('security_vulnerability', {}).get('vulnerable_version_range'),
            'First Patched Version': alert.get('security_vulnerability', {}).get('first_patched_version', {}).get('identifier'),
            'Created At': datetime.strptime(alert.get('created_at', ''), '%Y-%m-%dT%H:%M:%SZ').strftime('%Y-%m-%d %H:%M:%S') if alert.get('created_at') else None,
            'Updated At': datetime.strptime(alert.get('updated_at', ''), '%Y-%m-%dT%H:%M:%SZ').strftime('%Y-%m-%d %H:%M:%S') if alert.get('updated_at') else None,
            'Fixed At': datetime.strptime(alert.get('dismissed_at', ''), '%Y-%m-%dT%H:%M:%SZ').strftime('%Y-%m-%d %H:%M:%S') if alert.get('dismissed_at') else 'Not fixed yet',
            'Dismissed': bool(alert.get('dismissed_at')),
        }
        info.append(alert_info)
    
    return info

def get_dependabot_alert(git_repository: str) -> Optional[List[str]]:
    """
    Get the dependabot alerts about potential out of date libraries that have vulnerabilities from a GitHub repository.

    :param git_repository: Full path of the GitHub repository
    :type git_repository: str
    :return: List of CVEs or None if an error occurs
    :rtype: List[str]
    """
    github_token = os.environ.get('github_token')
    if not github_token:
        raise ValueError("GitHub token is not set in the environment variables")

    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"Bearer {github_token}",
    }
    base_url = "https://api.github.com/repos"
    parts = git_repository.split("/")
    user = parts[-2]
    repo = parts[-1]
    url = f"{base_url}/{user}/{repo}/dependabot/alerts"

    try:
        if not git_repository:
            raise ValueError("GitHub repository cannot be empty")

        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except ValueError as e:  # Handle ValueError separately
        logging.error(str(e))
        raise  # Re-raise the exception
    except requests.exceptions.RequestException as err:
        logging.error(f"Failed to fetch dependabot alerts. Error: {str(err)}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {str(e)}")
        return None

    data = response.json()
    cve_ids = []
    for alert in data:
        try:
            cve_ids.append(alert['security_advisory']['cve_id'])
        except KeyError:
            pass  # not all alerts have a CVE

    logging.info(f"Fetched dependabot alerts for repository: {git_repository}")
    data = extract_info(data)
    return(json.dumps(data, indent=4))

def get_user_name_from_access_key(iam_client: Any, access_key_id: str) -> Optional[str]:
    """Gets the username associated with a given access key.

    Args:
        iam_client (botocore.client.IAM): A low-level, session-aware Amazon IAM client.
        access_key_id (str): The access key ID to get the username for.

    Returns:
        str: The username associated with the access key, or None if an error occurred.
    """
    try:
        response = iam_client.list_users()
        for user in response['Users']:
            keys_response = iam_client.list_access_keys(UserName=user['UserName'])
            for key in keys_response['AccessKeyMetadata']:
                if key['AccessKeyId'] == access_key_id:
                    return user['UserName']
    except Exception as e:
        print(f"An error occurred while finding user name: {e}")
    return None

def deactivate_aws_key_helper(iam_client: Any, user_name: str, access_key: str) -> str:
    """Deactivates a given AWS access key.

    Args:
        iam_client (botocore.client.IAM): A low-level, session-aware Amazon IAM client.
        user_name (str): The username associated with the access key.
        access_key (str): The access key to deactivate.

    Returns:
        str: A message indicating whether the operation was successful or not.
    """
    try:
        response = iam_client.update_access_key(
            UserName=user_name,
            AccessKeyId=access_key,
            Status='Inactive'
        )
        response = "AWS Key deactivated successfully."
    except Exception as e:
        response = "An error occurred while deactivating the key: " + str({e})
    print("Response in helper: ", response)
    return response

def is_bucket_public(s3_client: Any, bucket_name: str) -> bool:
    """Check if a given S3 bucket is public.

    Args:
        s3_client (botocore.client.S3): A low-level, session-aware Amazon S3 client.
        bucket_name (str): The name of the S3 bucket.

    Returns:
        bool: True if the bucket is public, False otherwise.
    """
    try:
        # Check the bucket ACL
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        for grant in acl['Grants']:
            if (
                grant['Grantee']['Type'] == 'Group' and
                'AllUsers' in grant['Grantee']['URI']
            ):
                return True

        # Check the bucket policy
        try:
            policy = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_dict = json.loads(policy['Policy'])
            if 'Statement' in policy_dict:
                for statement in policy_dict['Statement']:
                    if (
                        statement['Effect'] == 'Allow' and
                        'Principal' in statement and
                        statement['Principal'] == '*'
                    ):
                        return True
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                raise
    except (BotoCoreError, ClientError) as e:
        logging.error(f"Error checking bucket {bucket_name}: {e}")
        return False

    return False

def extract_content_from_url(url):
    headers = {
        'User-Agent': 'AI Buddy Guard - Security Incident Schema Extractor'
    }
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        content = soup.get_text()
        return content
    else:
        print('Failed to fetch the webpage. Status code:', response.status_code)
        return None

llm_model = "gpt-4-0613"
temperature = 0
llm = ChatOpenAI(model=llm_model, temperature=temperature)

incident_schema = [
            {
                "name": "Incident_schema_extractor",
                "description": "Extract information about security incidents from text",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "incident date": {
                            "description": "Date when the incident occured or 'Unknown' if it is not clear",
                        },
                        "adversary": {
                            "type": "string",
                            "description": "Adversary group that caused the incident or 'Unknown' if it is not clear",
                        },
                        "adversary type": {
                            "type": "string",
                            "description": "The type of adversary group",
                            "enum": ["Nation State", "E-Criminal", "Hacktavist", "Researcher", "Unknown"]
                        },
                        "victim": {
                            "type": "string",
                            "description": "The company that was the victim of the security incident or 'Unknown' if it is not clear"
                        },
                        "victim industry": {
                            "type": "string",
                            "description": "The industry the victim falls into"
                        },
                        "adversary behavior": {
                            "type": "string",
                            "description": "Step by step explaination for what adversary did"
                        },
                        "initial access": {
                            "type": "string",
                            "description": "Intial access technique used by adversary"
                        },
                        "final goal": {
                            "type": "string",
                            "description": "What was the final goal of the adversary"
                        },
                        "auth related": {
                            "type": "string",
                            "description": "Is the issue related to authentication",
                            "enum": ["Yes", "No", "Unknown"]
                        },
                        "dependency related": {
                            "type": "string",
                            "description": "Is the incident related to 3rd party dependency",
                            "enum": ["Yes", "No", "Unknown"]
                        },
                        "prevention strategy": {
                            "type": "string",
                            "description": "How can I prevent this from happening to my company"
                        },
                    },
                    "required": ["adversary", "adversary type", "victim", "victim industry",  "adversary behavior", "initial access", "final goal", "auth related", "dependency related", "prevention strategy"],
                }
            }
        ]

def incident_extractor_tool(report):
    first_response = llm.predict_messages([HumanMessage(content=report)],
                                          functions=incident_schema)

    content = first_response.content
    function_call = first_response.additional_kwargs.get('function_call')

    if function_call is not None:
        content = function_call.get('arguments', content)

    try:
        content_dict = json.loads(content)
        print("Content dict: ", content_dict)
        return content_dict
    except json.JSONDecodeError:
        print(f"Warning: Could not parse JSON content: {content}")
        print(f"Content that caused the error: {report}")
        return None
    
def generate_threat_model(page_content):
    """
    This function generates a threat model based on the provided page content.

    Args:
        page_content (str): The content of the page for which to generate a threat model.

    Returns:
        str: The generated threat model.
    """
    prompt = "You are a cybersecurity expert. You job is to understand what the user is building, Identify what can go wrong and how to prevent: " + str(page_content)
    try:
        threat_model = llm.predict(prompt)
        return threat_model
    except Exception as e:
        logging.error(f"Error occurred while generating threat model: {e}")
        return None

def generate_required_tools_code(task_description):
    """This function uses OpenAI to generate code for all the Python functions needed for a task"""
    # Identify the required tools for the task
    tool_info = identify_required_tools(task_description)

    # Convert the tool info from JSON to a list of function definitions
    try:
        function_definitions = json.loads(tool_info)
    except json.JSONDecodeError as e:
        print(f"An error occurred while decoding the JSON: {str(e)}")
        return
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        return

    # Generate the code for each function
    code_for_all_tools = ""
    for function_definition in function_definitions:
        try:
            generated_code = generate_function_code(str(function_definition))
            code_for_all_tools += generated_code + "\n\n"
        except Exception as e:
            print(f"An error occurred while generating code: {str(e)}")

    # Write the generated code to a new file
    file_name = 'ai_buddy_guard/core/ai_generated_custom_tools.py'
    with open(file_name, 'w') as file:
        file.write(code_for_all_tools)
    return file_name

def identify_required_tools(task_description):
    """This function uses OpenAI to generate information about Python functions needed for a task"""
    task_prompt = """Your job is to figure out what kind of Python functions will be needed to accoplish a task from the user
    Provide the names for the functions and what they would need to do
    Provide the type of input and output the function would need to have
    Don't generate the code for it
    Please generate the output as a list of JSON objects
    Task:"""
    complete_prompt = task_prompt + task_description
    tool_info = llm.predict(complete_prompt)
    return tool_info

def generate_function_code(function_description):
    """This function uses OpenAI to generate code ouput"""
    code_prompt = """You job is to generate Python function code for what the user wants to achieve
    The code should be production ready with error handling inside the function
    It should be as broad as possible to solve the entire problem instead of just a small subset
    Only return the code, please never add any commentary around the code in the response
    Please apply an already existing custom decorator '@tool' to any function you generate
    Please add a well written docstring that starts with information about when this function should be used
    Please add type annotation in the function definition
    Please add this import "from langchain.tools import tool"
    User wants to """
    complete_code_prompt = code_prompt + function_description
    generated_code = llm.predict(complete_code_prompt)
    clean_code = remove_python_block_markers(generated_code)
    return clean_code

def remove_python_block_markers(code_block):
    code_without_start_marker = re.sub(r'```python\n', '', code_block)
    clean_code = re.sub(r'```', '', code_without_start_marker)
    return clean_code


