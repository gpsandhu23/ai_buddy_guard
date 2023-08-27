# AI Buddy Guard 🦾

## Overview

Buddy Guard is a prototype AI agent to test how well AI can help us find and fix security problems.

## Features

- **Code Scanning**: Uses AI algorithms to scan your codebase for security issues.
- **Cloud Security**: Checks for AWS S3 bucket vulnerabilities and more.
- **Easy to Use**: Simple web interface to get you started without any hassle.
- **Automated Fixes**: Offers suggestions and automated fixes for detected vulnerabilities.

## Installation

### Prerequisites

- Docker
- GitHub Personal Access Token for GitHub-related features

### Steps

```bash
# Clone the repository
git clone "repo"

# Navigate to the directory
cd aibuddyguard

# Build and run the Docker container
docker-compose up web_app
