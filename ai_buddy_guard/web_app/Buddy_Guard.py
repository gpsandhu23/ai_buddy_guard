# Standard library imports
from contextlib import contextmanager, redirect_stdout
from io import StringIO

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

# Input for git repository URL
user_instruction = st.text_input('What would you like to do?')
# When the Check button is pressed
if st.button('Start AI Agent'):
    if user_instruction:
        
        @contextmanager
        def st_capture(output_func):
            with StringIO() as stdout, redirect_stdout(stdout):
                old_write = stdout.write

                def new_write(string):
                    ret = old_write(string)
                    output_func(stdout.getvalue())
                    return ret
                
                stdout.write = new_write
                yield

        output = st.empty()
        with st_capture(output.code):
            # Pass the user input to run the AI Agent
            result = run_ai_bot(user_instruction)

        # Print results in a success block
        st.success(result)
    else:
        st.error('Please enter a git repository URL')