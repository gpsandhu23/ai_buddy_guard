import streamlit as st
from streamlit_option_menu import option_menu
from streamlit_extras.app_logo import add_logo
from streamlit_extras.add_vertical_space import add_vertical_space
from streamlit_extras.colored_header import colored_header

st.set_page_config(
    page_title="AI Buddy Guard",
    layout= "wide",
    # page_icon="🤖"
)

add_logo("ai_buddy_guard/web_app/logo.png", height=180)

colored_header(
    label=":green[AI Buddy Guard🦾]",
    description=None,
    color_name="green-90",
)

st.markdown("##### Settings")

hide_streamlit_style = """
            <style>
            #MainMenu {visibility: visible;}
            footer {visibility: hidden;}
                            footer:before {
                    content:'© 2023 Gurpartap Sandhu'; 
                    visibility:visible;
                    display: block;
                    }
            </style>
            """
st.markdown(hide_streamlit_style, unsafe_allow_html=True)

add_vertical_space(2)
# Template ends here



col1, col2, col3 = st.columns(3)

with col1:
   st.header("AI Mode")
   ai_mode = st.selectbox(
    'What tone do you want to the model to use?',
    ('Professional Helpful Assistant', 'Silicon Valley Developer', 'Marvel Superfan', 'Soccer Fanatic', 'Pretentious Pirate'))
   
with col2:
   st.header("Model")
   model_used = st.selectbox(
    'Which AI Model would you like to use?',
    ('gpt-4', 'gpt-3.5-turbo-16k', 'gpt-3.5-turbo'))
   

with col3:
   st.header("Self hosted model")
   self_hosted_model_url = st.text_input('What is the url for your self hosted model', placeholder="Acme Corp Special LLM", disabled=True)

st.session_state['ai_mode'] = ai_mode
st.session_state['model'] = model_used
st.session_state['self_hosted_model_url'] = self_hosted_model_url
# st.session_state


add_vertical_space(2)


col4, col5, col6 = st.columns(3)

with col4:
   st.header("Authentication System")
   auth_system_name = st.text_input('What is the name of your authentication system', placeholder="Acme Corp Identity System")
   
with col5:
   st.header("Secret Storage Solution")
   secret_storage_solution = st.text_input('What is the name of your recommended secret storage solution', placeholder="Acme Corp Special Secret Store")
   
with col6:
   st.header("Patch Management")
   patch_management_solution = st.text_input('What is the name of your recommended patch management solution', placeholder="Acme Corp Special Patch Management Solution")

st.session_state['auth_system'] = auth_system_name
st.session_state['secrets_solution'] = secret_storage_solution
st.session_state['patching_solution'] = patch_management_solution
# st.session_state