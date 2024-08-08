import docx
import streamlit as st
import PyPDF2
import os
import sqlite3
from cryptography.fernet import Fernet
import io
from fpdf import FPDF
from sqlalchemy import create_engine, Table, Column, Integer, String, MetaData
from docx import Document

# Initialize encryption key
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Database setup
engine = create_engine('sqlite:///document_query.db')
meta = MetaData()

users = Table(
    'users', meta,
    Column('id', Integer, primary_key=True),
    Column('username', String),
    Column('password', String)  # This should be hashed in a real application
)

documents = Table(
    'documents', meta,
    Column('id', Integer, primary_key=True),
    Column('user_id', Integer),
    Column('content', String)  # Encrypted content
)

queries = Table(
    'queries', meta,
    Column('id', Integer, primary_key=True),
    Column('user_id', Integer),
    Column('query_text', String),
    Column('response', String),
    Column('timestamp', String)
)

meta.create_all(engine)


# Secure login function
def secure_login(username, password):
    with engine.connect() as conn:
        query = users.select().where(users.c.username == username)
        result = conn.execute(query).fetchone()
        if result and result['password'] == password:
            return True
    return False


# Function to read documents
def read_document(file):
    if file.type == "application/pdf":
        reader = PyPDF2.PdfFileReader(file)
        text = ""
        for page in range(reader.numPages):
            text += reader.getPage(page).extract_text()
    elif file.type == "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
        doc = docx.Document(file)
        text = "\n".join([para.text for para in doc.paragraphs])
    elif file.type == "text/plain":
        text = file.read().decode('utf-8')
    else:
        text = ""
    return text


# Function to handle user queries
def handle_query(query, doc_text):
    # Implement search functionality here, simple keyword search for now
    if query.lower() in doc_text.lower():
        return f"Found the query in the document."
    else:
        return f"No match found."


# Main Streamlit interface
def main():
    st.title("Document Query Application")

    # User login
    st.sidebar.title("Login")
    username = st.sidebar.text_input("Username")
    password = st.sidebar.text_input("Password", type="password")

    if st.sidebar.button("Login"):
        if secure_login(username, password):
            st.success("Logged in successfully!")
        else:
            st.error("Invalid credentials")

    # Document upload
    st.header("Upload Document")
    uploaded_file = st.file_uploader("Choose a document", type=["pdf", "docx", "txt"])

    if uploaded_file:
        doc_text = read_document(uploaded_file)

        # Encrypt and store the document
        encrypted_content = cipher_suite.encrypt(doc_text.encode('utf-8'))
        with engine.connect() as conn:
            conn.execute(documents.insert().values(user_id=1, content=encrypted_content))

        st.success("Document uploaded successfully!")

    # Query input
    st.header("Query Document")
    query = st.text_input("Enter your query")

    if query:
        # Retrieve and decrypt the document
        with engine.connect() as conn:
            doc_result = conn.execute(documents.select().where(documents.c.user_id == 1)).fetchone()
            decrypted_content = cipher_suite.decrypt(doc_result['content'].encode('utf-8')).decode('utf-8')

        # Handle the query
        response = handle_query(query, decrypted_content)
        st.write(response)

        # Store the query history
        with engine.connect() as conn:
            conn.execute(queries.insert().values(user_id=1, query_text=query, response=response, timestamp="now"))

    # Download chat history
    if st.button("Download Chat History"):
        with engine.connect() as conn:
            query_result = conn.execute(queries.select().where(queries.c.user_id == 1)).fetchall()

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)

        for record in query_result:
            pdf.multi_cell(0, 10, f"Query: {record['query_text']}\nResponse: {record['response']}\n\n")

        pdf_output = io.BytesIO()
        pdf.output(pdf_output)

        st.download_button(
            label="Download Chat History",
            data=pdf_output.getvalue(),
            file_name="chat_history.pdf",
            mime="application/pdf"
        )


if __name__ == "__main__":
    main()
