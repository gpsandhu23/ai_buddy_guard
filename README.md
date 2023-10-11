# AI Buddy Guard 🦾

## Overview

Buddy Guard is a prototype AI agent to test how well AI can help us find and fix security problems.

## Features

- **Secret Scanning**: Finds any leaked crdentials in your code
- **Out of date dependencies**: Finds any vulnerable dependencies in your git repo
- **Open S3 buckets**: Checks for any open AWS S3 buckets
- **Missing MFA for AWS**: Find users that don't have MFA enabled on AWS
- **Extract incident schema**: Extract key insights about a security incident in a parsable schema from natural language text reports
- **Check CVE in KEV list**: Check if a CVE is in the CISA KEV list
- **Threat model**: Generate a basic threat model for a service given a url to documentation
- **Invalidate AWS Key**: Invalite an AWS key if it has been compromised
- **Webpage phishing check**: Check if a URL is a phishing webpage based on content, WHOIS records, TLS cert info and DNS records

## Installation

### Prerequisites

- **Docker**
- **GitHub Personal Access Token for GitHub-related features**
- **AWS tokens for AWS-related features**

### Steps

```bash
# Clone the repository
git clone https://github.com/gpsandhu23/ai_buddy_guard.git

# Navigate to the directory
cd aibuddyguard

# Build and run the Docker container
docker-compose up web_app