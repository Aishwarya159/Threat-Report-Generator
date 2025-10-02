# Threat-Report-Generator
A python project that can extract detect CVEs and threats actors from PDFs uploaded vis FAST API and store them in SQLite database. Also, provides an API to query the  CVE and threat actor data from the uploaded files.

**Setup:
**
1. Dowload the required libraries using pip
$pip install SQLAlchemy fastapi_filter pydantic-ai openrouter-agent 'pydantic-ai-slim[openai]' fastapi uvicorn python-multipart pydantic_ai  PyMuPDF                                                                 
3. From the directory of the main file, run the fast api using uvicorn using the below command:
uvicorn main:app --reload
4. Once the API is up and running, you can access the endpoints UI using the below link:
http://127.0.0.1:8000/
5. You can upload new PDFs using the upload-pdf endpoint
6. You can query the tables using the search end point (Note: In the search end point, select true for the show_pdf if you need PDF details, show_actor for threat actor details and show_cve for CVEs. You can view multiple things at once by setting multiple show variables to true)

