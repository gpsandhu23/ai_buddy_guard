# Standard library imports
import json
import logging
import os

# Third-party imports
import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from langchain.agents import AgentType, initialize_agent, load_tools
from langchain.chat_models import ChatOpenAI
from langchain.tools import StructuredTool, tool

# Local (or relative) imports
from .utils import (
    deactivate_aws_key_helper,
    get_dependabot_alert,
    get_user_name_from_access_key,
    is_bucket_public,
    scan_git_secrets,
)
# Initialize logging
logging.basicConfig(level=logging.INFO)

@tool
def check_credentials_in_repo(git_repo: str) -> str:
    """Please always use this function to check if a git repository has any security issues due to leaked credentials
    Leaked credentials can be a big security issue"""
    results = scan_git_secrets(git_repo)
    return results

@tool
def check_git_depdency_cves(git_repo:str) -> str:
    """Please use this tool to check for security issues in a git repo due to potential vulnerabilities due to out of date dependencies.
    Use this tool if you need to check for any out of date dependencies with security issues"""
    results = get_dependabot_alert(git_repo)
    return results

@tool
def invalidate_aws_key(access_key: str) -> str:
    """Please always use this tool if you find any leaked AWS credentials to fix security issue.
    It returns 'AWS Key invalidated successfully' if it worked
    It returns 'No user found for the given access key' if the use for this key doesn't exist. This happens if the key is already invalidated.
    Please pass the string for the key in the following format: 'AKIAxxxxxxxxxxxxx'
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
    """Use this tool to notify the security operation center if any security issues are found.
    Returns 'Message posted successfully' if message is delivered and 
    'Error posting message' if there are any issues notifying the security operation center.
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

def run_ai_bot(user_input):
    """Run the AI bot"""
    agent_instruction = user_input
    llm = ChatOpenAI(temperature=0)
    tools = load_tools([], llm=llm)

    agent= initialize_agent(
        tools + [check_credentials_in_repo] + [check_git_depdency_cves] + [get_public_buckets] + [check_aws_mfa] + [invalidate_aws_key], 
        llm, 
        agent=AgentType.OPENAI_FUNCTIONS,
        handle_parsing_errors=True,
        verbose = True)

    result = agent(agent_instruction)
    # result = check_aws_mfa(user_input)
    return result