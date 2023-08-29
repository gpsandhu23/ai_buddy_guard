# Standard library imports
import json
import logging
import os
from typing import List, Union

# Third-party imports
import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from langchain.agents import AgentType, initialize_agent, load_tools
from langchain.chat_models import ChatOpenAI
from langchain.tools import StructuredTool, tool
import pandas as pd

# Local (or relative) imports
from .utils import (
    deactivate_aws_key_helper,
    get_dependabot_alert,
    get_user_name_from_access_key,
    is_bucket_public,
    scan_git_secrets,
    extract_content_from_url,
    incident_extractor_tool,
    generate_threat_model

)
# Initialize logging
logging.basicConfig(level=logging.INFO)

@tool
def check_credentials_in_repo(git_repo: str) -> str:
    """
    This function checks a given git repository for any leaked credentials.
    
    Leaked credentials in a repository can pose a significant security risk. This function uses the scan_git_secrets method
    to scan the repository and return any findings.
    
    Parameters:
    git_repo (str): The URL of the git repository to check.
    
    Returns:
    results (str): The results of the scan for leaked credentials.
    """
    results = scan_git_secrets(git_repo)
    return results

@tool
def check_git_depdency_cves(git_repo:str) -> str:
    """
    This function checks a given git repository for potential vulnerabilities due to out-of-date dependencies.
    
    Out-of-date dependencies can have known security vulnerabilities that pose a risk to the repository. This function uses
    the get_dependabot_alert method to check the repository's dependencies and return any findings.
    
    Parameters:
    git_repo (str): The URL of the git repository to check.
    
    Returns:
    results (str): The results of the check for out-of-date dependencies with security issues.
    """
    results = get_dependabot_alert(git_repo)
    return results

@tool
def invalidate_aws_key(access_key: str) -> str:
    """
    This function invalidates a given AWS access key to mitigate the security risk associated with leaked credentials.
    
    If the operation is successful, it returns 'AWS Key invalidated successfully'.
    If the user associated with the key doesn't exist (which may occur if the key is already invalidated), it returns 'No user found for the given access key'.
    
    Parameters:
    access_key (str): The AWS access key to invalidate. It should be in the format: 'AKIAxxxxxxxxxxxxx'.
    
    Returns:
    response (str): The result of the key invalidation operation.
    """
    iam_client = boto3.client('iam')
    user_name = get_user_name_from_access_key(iam_client, access_key)
    if user_name:
        response = deactivate_aws_key_helper(iam_client, user_name, access_key)
    else:
        response = "No user found for the given access key: " +  str({access_key})
    print("Response in tool: ", response)
    return response

slack_token = os.getenv("slack_api_key")

@tool
def inform_SOC(message: str) -> str:
    """
    This function sends a notification to the security operation center (SOC) when a security issue is detected.
    
    If the message is delivered successfully, it returns 'Message posted successfully'.
    If there are any issues in notifying the SOC, it returns 'Error posting message'.
    
    Parameters:
    message (str): The message to be sent to the SOC.
    
    Returns:
    response (str): The result of the message delivery operation.
    """
    client = WebClient(token=slack_token)

    # Send a message to the channel
    response = client.chat_postMessage(
    channel='#soc',
    text=message
    )

    # Check the response
    if response['ok']:
        response = print('Message posted successfully.')
    else:
        response = print(f"Error posting message: {response['error']}")
    return response

@tool
def get_public_buckets(aws_account_name: str) -> list:
    """Use this tool to check if S3 buckets are left open and unautenticated for an AWS account.
    This can be a security issue in AWS account.
    It returns the list of buckets that are open and an empty list if there are no open buckets.
    Having an AWS bucket open is serious and you should inform the SOC if I have any open buckets."""
    s3_client = boto3.client('s3')
    print("Checking buckets in account: ", aws_account_name)

    # Get list of all bucket names
    response = s3_client.list_buckets()
    all_buckets = [bucket['Name'] for bucket in response['Buckets']]

    # Check each bucket to see if it's public
    public_buckets = []
    for bucket in all_buckets:
        if is_bucket_public(s3_client, bucket):
            public_buckets.append(bucket)

    return public_buckets

@tool
def check_aws_mfa(account: str) -> list:
    """Checks AWS account for users that don't have MFA enabled on platform AWS and returns them.
    Returns an empty list if there are no users without MFA on platform AWS."""
    users_without_mfa = []
    try:
        logging.info("Checking users in AWS account: %s", account)
        client = boto3.client('iam')
        users = client.list_users()['Users']
    except (NoCredentialsError, BotoCoreError, ClientError) as error:
        logging.error("Failed to retrieve IAM users: %s", error)
        return []

    for user in users:
        try:
            client.get_login_profile(UserName=user['UserName'])  # check if user has console access
            mfa_devices = client.list_mfa_devices(UserName=user['UserName'])
            if not mfa_devices['MFADevices']:
                users_without_mfa.append(user['UserName'])
        except ClientError as error:
            # If the error message is about the user not having a login profile, skip this user
            if error.response['Error']['Code'] == 'NoSuchEntity':
                continue
            else:
                logging.error("Failed to retrieve MFA devices or console access for user %s: %s", user['UserName'], error)

    return users_without_mfa

@tool
def extract_incident_schema(incident_url: str) -> dict:
    """
    This function extracts interesting insights about an incident from a given URL.

    The insights are returned as a dictionary, which can include various details about the incident such as the type of incident, the entities involved, the impact, and any remedial actions taken.

    Parameters:
    incident_url (str): The URL from which to extract incident insights.

    Returns:
    insights (dict): A dictionary containing interesting insights about the incident.
    """
    incident_content = extract_content_from_url(incident_url)
    incident_dict = incident_extractor_tool(incident_content)
    return incident_dict

@tool
def check_cve_in_kev(cve_string: str) -> Union[List[str], str]:
    """
    This function checks if a list of CVEs is actively being exploited in the wild and is part of the KEV list.
    It prioritizes CVEs that are being exploited in the wild as they pose a significant security risk.
    The function returns a list of exploited CVEs or an empty list if none are found.

    Parameters:
    cve_string (str): A string of CVEs separated by commas.

    Returns:
    exploited_cves (Union[List[str], str]): A list of CVEs that are being exploited in the wild or an error message if an error occurs.
    """
    cisa_kev_url = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
    
    try:
        df = pd.read_csv(cisa_kev_url)
    except Exception as e:
        logging.error(f"Error occurred while reading CSV: {e}")
        return f"Error occurred while reading CSV: {e}"
    
    if 'cveID' not in df.columns:
        logging.error("Error: 'CVE' column not found in DataFrame")
        return "Error: 'CVE' column not found in DataFrame"

    try:
        cve_list = [cve.strip() for cve in cve_string.split(",")]
    except Exception as e:
        logging.error(f"Error occurred while splitting the CVE string: {e}")
        return f"Error occurred while splitting the CVE string: {e}"

    exploited_cves = [cve for cve in cve_list if cve in df['cveID'].values]
    logging.info(f"Exploited CVEs found: {exploited_cves}")

    return exploited_cves

@tool
def threat_model(url: str) -> str:
    """
    This function generates a threat model for a given URL.
    
    It first retrieves the content from the URL using the get_content_from_url function. 
    Then, it passes the retrieved content to the generate_threat_model function to generate the threat model.
    
    Parameters:
    url (str): The URL for which to generate the threat model.
    
    Returns:
    threat_model (str): The generated threat model.
    """
    try:
        content = extract_content_from_url(url)
    except Exception as e:
        logging.error(f"Error occurred while getting content from URL: {e}")
        return f"Error occurred while getting content from URL: {e}"

    try:
        threat_model = generate_threat_model(content)
    except Exception as e:
        logging.error(f"Error occurred while generating threat model: {e}")
        return f"Error occurred while generating threat model: {e}"

    return threat_model

    

def run_ai_bot(user_input):
    """
    This function initializes and runs the AI bot with a set of predefined tools. 
    These tools include checking credentials in a repository, checking for outdated dependencies in a git repository,
    checking for public S3 buckets, checking for AWS users without MFA, and invalidating leaked AWS keys.
    
    Parameters:
    user_input (str): The instruction for the AI bot to execute.
    
    Returns:
    result: The result of the executed instruction.
    """
    agent_instruction = user_input
    llm = ChatOpenAI(temperature=0)
    tools = load_tools([], llm=llm)

    agent= initialize_agent(
        tools + [check_credentials_in_repo] + [check_git_depdency_cves] + [get_public_buckets] + [check_aws_mfa] 
        + [invalidate_aws_key] + [extract_incident_schema] + [check_cve_in_kev] + [threat_model], 
        llm, 
        agent=AgentType.OPENAI_FUNCTIONS,
        handle_parsing_errors=True,
        verbose = True)

    result = agent(agent_instruction)
    # result = check_aws_mfa(user_input)
    return result