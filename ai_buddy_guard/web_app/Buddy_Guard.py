# Standard library imports
from contextlib import contextmanager, redirect_stdout
from io import StringIO
import re

# Third-party imports
import streamlit as st
from streamlit_extras.add_vertical_space import add_vertical_space
from streamlit_extras.app_logo import add_logo
from streamlit_extras.colored_header import colored_header

# Local imports
from ai_buddy_guard.core.core import run_ai_bot


def setup_page():
    """Set up the Streamlit page with custom configuration."""

    # Configure Streamlit page settings
    st.set_page_config(
        page_title="AI Buddy Guard",
        layout="wide",
        page_icon="🦾"
    )

    # Add logo and header to the page
    add_logo_and_header()

    # Customize CSS
    customize_css()

    add_vertical_space(2)

def add_logo_and_header():
    """Add logo and header to the Streamlit page."""
    add_logo("ai_buddy_guard/web_app/logo.png", height=180)
    colored_header(
        label=":green[AI Buddy Guard🦾]",
        description=None,
        color_name="green-90",
    )
    st.markdown("##### Finding and fixing security problems using AI")

def customize_css():
    """Customize CSS for the Streamlit page."""
    hide_streamlit_style = """
                <style>
                #MainMenu {visibility: visible;}
                footer {visibility: hidden;
                }
                footer:before {
                    content:'© 2023 Gurpartap Sandhu'; 
                    visibility:visible;
                    display: block;
                    }
                </style>
                """
    st.markdown(hide_streamlit_style, unsafe_allow_html=True)

# Call the function to set up the page
setup_page()

def strip_ansi_escape_sequences(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


# Request user input for task instruction
user_instruction = st.text_input('Enter your task instruction:')
# Check if the 'Start AI Agent' button is pressed
if st.button('Start AI Agent'):
     # Check if user instruction is provided
     if user_instruction:
         # Context manager to capture stdout and stderr
         @contextmanager
         def st_capture(output_func):
             with StringIO() as stdout, redirect_stdout(stdout):
                 old_write = stdout.write
                 # New write function to clean and output the string
                 def new_write(string):
                     ret = old_write(string)
                     clean_string = strip_ansi_escape_sequences(stdout.getvalue())
                     output_func(clean_string)
                     return ret
                 stdout.write = new_write
                 yield
         # Placeholder for output
         output = st.empty()
         # Capture the output of the AI agent process
         with st_capture(output.code):
             # Execute the AI agent process with user instruction
             try:
                 result = run_ai_bot(user_instruction)
             except Exception as e:
                 result = f"An error occurred while processing your task: {str(e)}"
         # Display the result in a success block if no exception occurred
         if "An error occurred" not in result:
             st.success(result)
         else:
             st.error(result)
     else:
         # Display error message if no user instruction is provided
         st.error('Please enter your task instruction.')