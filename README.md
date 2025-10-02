# Threat-Report-Generator
A python project that can extract detect CVEs and threats actors from PDFs uploaded vis FAST API and store them in SQLite database. Also, provides an API to query the  CVE and threat actor data from the uploaded files.

Setup
1. Dowload the required libraries using pip
$pip install SQLAlchemy fastapi_filter pydantic-ai openrouter-agent 'pydantic-ai-slim[openai]' fastapi uvicorn python-multipart pydantic_ai  PyMuPDF                                                                 
3. From the directory of the main file, run the fast api using uvicorn using the below command:
uvicorn main:app --reload
4. Once the API is up and running, you can access the endpoints UI using the below link:
http://127.0.0.1:8000/
5. You can upload new PDFs using the upload-pdf endpoint
6. You can query the tables using the search end point (Note: In the search end point, select true for the show_pdf if you need PDF details, show_actor for threat actor details and show_cve for CVEs. You can view multiple things at once by setting multiple show variables to true)

Design decisions:
1. I have used pydantic AI agents as the task is simple but we need multiple kinds of data in certain format to put them in the SQLite DB, hence pydantic AI is a good choice
2. I have created two agents one for CVEs and one for extracting threat actors as both are independent task and the AI agents performed better when separate agents were used for each task
3. I have used fast api filters using SQL alchemy to query the tables
4. I have used NVIDIA's nemotron model as it is good at returning JSOn outputs

Testing:
1. I have done manual testing of the API using the sample files in the threat reports folder
