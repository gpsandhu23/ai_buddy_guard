# Use an official Python runtime as a parent image
FROM python:3.9

# Set the working directory in the container to /app
WORKDIR /ai_buddy_guard

# Set the Python path
ENV PYTHONPATH /ai_buddy_guard

# Add the current directory contents into the container at /app
ADD . /ai_buddy_guard/

# Upgrade pip
RUN pip install --upgrade pip

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Run app.py when the container launches
CMD ["streamlit", "run", "ai_buddy_guard/web_app/AI_Buddy_Guard.py"]
